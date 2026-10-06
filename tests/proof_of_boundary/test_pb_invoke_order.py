# PB-6: Backbone Invoke Order Verification — RET-C2-256
#
# Verifies that a full Graph().invoke() with a VERIFIED_EXTERNAL caller executes
# the 5-node backbone in the correct order:
#   InitializeNode → PreProcessNode → ShiftHandoverGraphNode → PostProcessNode → FinalizeNode
#
# Rules:
#   - Caller trust level MUST be VERIFIED_EXTERNAL (not InvocationContext.for_internal())
#     so the invoke path exercises the real external trust gate on pre_process.
#   - The valid payload MUST yield AgentStatus.SUCCESS — a non-SUCCESS status
#     short-circuits post_process and the assertion is invalid.
#   - Assert result.get("output") (not result.get("formatted_output")) — the invoke
#     surface exposes "output" only.
#   - Assert result["status"] == AgentStatus.SUCCESS.value ('success' string) — the
#     real SDK's invoke() returns the serialised state where enums become their string
#     values. Compare against .value for an explicit, robust assertion.
#   - Mute emit_trace_event in each node module via monkeypatch.setattr — the real
#     SDK's emit_trace_event requires a live audit backend; without muting it raises
#     inside the node execute() path, the framework catches the exception silently
#     and returns status='error' with error_log=[].
#   - Do NOT stub shared.* in sys.modules — patch module-level name bindings only.
#
# References: a peer template canonical PB-6; BUILD_HANDOFF rule #8.

import importlib

from framework.schemas.agent_status import AgentStatus
from framework.schemas.invocation_context import InvocationContext
from framework.schemas.trust_level import TrustLevel
from tests.fixtures import BASE_REQUEST, as_input

# ---------------------------------------------------------------------------
# Template-specific constants
# ---------------------------------------------------------------------------

# The class name string of the `main`-slot GraphNode in src/graph/graph.py.
_MAIN_SLOT_NODE = "ShiftHandoverGraphNode"

# A valid shift payload that yields AgentStatus.SUCCESS through all 6 inner nodes.
# Taken from tests/fixtures.py, which is also where deploy/invoke_payload.json is
# generated from, so this test and the deployment smoke check cannot end up
# asserting different entry contracts.
_VALID_PAYLOAD = as_input(BASE_REQUEST)

# ---------------------------------------------------------------------------
# Node modules to patch (mute emit_trace_event — no audit backend in CI)
# ---------------------------------------------------------------------------

_NODE_MODULES = [
    "src.nodes.pre_process_node",
    "src.nodes.input_parse_node",
    "src.nodes.anomaly_detect_node",
    "src.nodes.waste_format_node",
    "src.nodes.report_generate_node",
    "src.nodes.multilingual_adapt_node",
    "src.nodes.response_validate_node",
    "src.nodes.post_process_node",
]


def _mute_emit(monkeypatch):
    """Patch emit_trace_event in all node modules to a no-op.

    The real SDK's emit_trace_event requires a live audit backend.
    Patch the module-level name binding (safe; does not stub shared.* in
    sys.modules) so the full Graph().invoke() path works in CI without a
    live audit service.
    """
    for mod_path in _NODE_MODULES:
        mod = importlib.import_module(mod_path)
        monkeypatch.setattr(mod, "emit_trace_event", lambda *a, **k: None)


def _invoke(payload: str = _VALID_PAYLOAD) -> dict:
    """Run RetailFranchiseShiftHandoverReportAgent.invoke() with VERIFIED_EXTERNAL."""
    from src.graph.graph import RetailFranchiseShiftHandoverReportAgent

    agent = RetailFranchiseShiftHandoverReportAgent()
    agent.compile()
    ctx = InvocationContext(caller_trust_level=TrustLevel.VERIFIED_EXTERNAL)
    return agent.invoke(payload, ctx=ctx)


# ---------------------------------------------------------------------------
# PB-6 Tests
# ---------------------------------------------------------------------------


class TestPB6BackboneInvokeOrder:
    """PB-6: Full Graph().invoke() must execute backbone nodes in the correct order.

    This test exercises the real VERIFIED_EXTERNAL caller path end-to-end,
    including the S-1 trust gate on PreProcessNode and the full DomainWorkflowGraph.
    emit_trace_event is muted per-test via monkeypatch (no audit backend in CI).
    """

    def test_backbone_order_success_path(self, monkeypatch):
        """PB-6 main: backbone invoke order matches expected 5-node sequence.

        A VERIFIED_EXTERNAL caller sends a valid shift JSON payload.
        The agent must:
          1. Return status == AgentStatus.SUCCESS.value ('success')
          2. Return a non-empty result["output"]
          3. Record node_history with InitializeNode first, FinalizeNode last,
             and ShiftHandoverGraphNode (the main-slot GraphNode) in between.
        """
        _mute_emit(monkeypatch)
        result = _invoke()

        # Status must be SUCCESS (serialised as string value by the real SDK invoke())
        assert result.get("status") == AgentStatus.SUCCESS.value, (
            f"Expected status={AgentStatus.SUCCESS.value!r}, got {result.get('status')!r}. "
            f"error_log: {result.get('error_log', [])}"
        )

        # output must be non-empty (FinalizeNode exposes result as output)
        assert result.get("output"), (
            "result['output'] must not be empty — "
            "check that ResponseValidateNode set validated_output and "
            "PostProcessNode forwarded it as formatted_output"
        )

        # Backbone node history must start with InitializeNode and end with FinalizeNode
        node_history = result.get("node_history", [])
        assert node_history, "node_history is empty — backbone did not record execution"
        assert node_history[0] == "InitializeNode", (
            f"Expected node_history[0]='InitializeNode', got {node_history[0]!r}. " f"Full history: {node_history}"
        )
        assert node_history[-1] == "FinalizeNode", (
            f"Expected node_history[-1]='FinalizeNode', got {node_history[-1]!r}. " f"Full history: {node_history}"
        )

        # Main-slot node must appear in the history
        assert _MAIN_SLOT_NODE in node_history, (
            f"Expected {_MAIN_SLOT_NODE!r} in node_history. " f"Full history: {node_history}"
        )

        # Relative order: backbone nodes before and after main-slot
        pre_idx = next(
            (i for i, n in enumerate(node_history) if "PreProcess" in n or "PreProcess" == n),
            None,
        )
        main_idx = next((i for i, n in enumerate(node_history) if n == _MAIN_SLOT_NODE), None)
        post_idx = next((i for i, n in enumerate(node_history) if "PostProcess" in n), None)

        if pre_idx is not None and main_idx is not None:
            assert pre_idx < main_idx, (
                f"PreProcessNode must come before {_MAIN_SLOT_NODE} in node_history. " f"Full history: {node_history}"
            )
        if main_idx is not None and post_idx is not None:
            assert main_idx < post_idx, (
                f"{_MAIN_SLOT_NODE} must come before PostProcessNode in node_history. " f"Full history: {node_history}"
            )

    def test_result_output_is_japanese_report(self, monkeypatch):
        """PB-6 output check: result['output'] contains Japanese shift report content."""
        _mute_emit(monkeypatch)
        result = _invoke()

        assert result.get("status") == AgentStatus.SUCCESS.value, (
            f"Expected status={AgentStatus.SUCCESS.value!r}, got {result.get('status')!r}. "
            f"error_log: {result.get('error_log', [])}"
        )
        output = result.get("output", "")
        # The output is the validated_output assembled by ResponseValidateNode:
        # Japanese Moshiokuri-sho + bilingual JA+VI/EN summary.
        assert (
            "申し送り書" in output or "LAWSON-7-001" in output
        ), f"Expected Japanese shift report content in output; got: {output[:200]!r}"
