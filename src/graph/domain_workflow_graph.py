"""AgentCore Platform v1.0"""

# RET-C2-256 — DomainWorkflowGraph (inner BaseGraph)
#
# This is the INNER graph for the Cat 2 nested architecture.
# It encapsulates the full franchise shift handover report domain workflow:
#
#   START
#     → input_parse        (InputParseNode)        — parse + validate shift JSON
#     → anomaly_detect     (AnomalyDetectNode)      — flag operational anomalies
#     → waste_format       (WasteFormatNode)        — Shokuhin-Loss regulatory log
#     → report_generate    (ReportGenerateNode)     — Japanese Moshiokuri-sho
#     → multilingual_adapt (MultilingualAdaptNode)  — bilingual JA+VI/EN summary
#     → response_validate  (ResponseValidateNode)   — S-3 output gate
#   → END
#
# Called by ShiftHandoverGraphNode.get_subgraph() in graph.py.
# get_output() shapes the sub_result consumed by ShiftHandoverGraphNode.merge_output().
#
# Rules enforced:
#   ✅ Inherits BaseGraph (fully custom topology — no forced backbone)
#   ✅ Implements all 7 BaseGraph ABC methods
#   ✅ register_nodes() does NOT call super() (abstract in BaseGraph)
#   ✅ Does NOT register initialize / finalize (outer backbone concerns)
#   ✅ get_output() designed together with ShiftHandoverGraphNode.merge_output()
#   ✅ All inner nodes: required_trust_level = ANONYMOUS
#   ❌ No Level 0 platform SDK imports
#   ❌ Not placed under src/subagents/

from typing import Any, Dict

from langgraph.graph import END, START

from framework.graph.base_graph import BaseGraph
from framework.schemas.agent_state import AgentState
from framework.schemas.agent_status import AgentStatus
from src.nodes.anomaly_detect_node import AnomalyDetectNode
from src.nodes.input_parse_node import InputParseNode
from src.nodes.multilingual_adapt_node import MultilingualAdaptNode
from src.nodes.report_generate_node import ReportGenerateNode
from src.nodes.response_validate_node import ResponseValidateNode
from src.nodes.waste_format_node import WasteFormatNode
from src.schemas.state import State


class DomainWorkflowGraph(BaseGraph):
    """Inner domain workflow graph for RET-C2-256.

    Inherits BaseGraph directly for a fully custom node topology.
    Called by ShiftHandoverGraphNode.get_subgraph() in graph.py.

    Pipeline (linear — 6 domain nodes):
        START
          → input_parse        (InputParseNode)
          → anomaly_detect     (AnomalyDetectNode)
          → waste_format       (WasteFormatNode)
          → report_generate    (ReportGenerateNode)
          → multilingual_adapt (MultilingualAdaptNode)
          → response_validate  (ResponseValidateNode)
        → END

    All nodes are FunctionNode subclasses with required_trust_level = ANONYMOUS.
    initialize / finalize are outer backbone concerns — not registered here.
    """

    # ── Identity ──────────────────────────────────────────────────────────────

    @property
    def name(self) -> str:
        """Unique identifier for this inner graph."""
        return "ret_c2_256_domain_workflow"

    @property
    def state_schema(self) -> type:
        """TypedDict subclass shared across inner and outer graph."""
        return State

    # ── Config validation ─────────────────────────────────────────────────────

    def _validate_config(self) -> None:
        """Validate inner graph config before compilation.

        No mandatory config keys for v1 — domain nodes are self-contained.
        """
        pass

    # ── Node registration ─────────────────────────────────────────────────────

    def register_nodes(self) -> None:
        """Register all 6 domain nodes.

        No super() call — BaseGraph.register_nodes() is abstract.
        Do NOT register initialize or finalize; those are outer backbone
        concerns handled by AgentBaseGraph in graph.py.
        Every key registered here is referenced in add_edges().

        All nodes instantiated with NO constructor arguments (SDK-v1 contract).
        Config flows per-call via execute(self, state, config=None).
        """
        self._nodes["input_parse"] = InputParseNode()
        self._nodes["anomaly_detect"] = AnomalyDetectNode()
        self._nodes["waste_format"] = WasteFormatNode()
        self._nodes["report_generate"] = ReportGenerateNode()
        self._nodes["multilingual_adapt"] = MultilingualAdaptNode()
        self._nodes["response_validate"] = ResponseValidateNode()

    # ── Edge wiring ───────────────────────────────────────────────────────────

    def add_edges(self) -> None:
        """Wire the linear shift handover report domain topology.

        Pipeline is intentionally linear — anomaly detection, waste formatting,
        and report generation are sequential steps; each depends on prior outputs.
        route() is implemented as required by the ABC but add_conditional_edges()
        is not used in v1.

        Flow:
            START → input_parse → anomaly_detect → waste_format
                 → report_generate → multilingual_adapt → response_validate → END
        """
        self._sg.add_edge(START, "input_parse")
        self._sg.add_edge("input_parse", "anomaly_detect")
        self._sg.add_edge("anomaly_detect", "waste_format")
        self._sg.add_edge("waste_format", "report_generate")
        self._sg.add_edge("report_generate", "multilingual_adapt")
        self._sg.add_edge("multilingual_adapt", "response_validate")
        self._sg.add_edge("response_validate", END)

    # ── Routing ───────────────────────────────────────────────────────────────

    def route(self, state: AgentState) -> str:
        """Conditional routing — required by BaseGraph ABC.

        For this linear topology add_conditional_edges() is not used, so this
        method is never called at runtime. Returns END on error so an unexpected
        call does not re-enter a processing node.
        """
        if state.get("status") == AgentStatus.ERROR.value:
            return END
        return "response_validate"

    # ── Output shape ──────────────────────────────────────────────────────────

    def get_output(self, state: AgentState) -> Dict[str, Any]:
        """Shape the output dict returned to the outer graph as sub_result.

        This dict is received by ShiftHandoverGraphNode.merge_output()
        in graph.py as the `sub_result` argument. Both methods are designed
        together to guarantee field-name consistency:

            Inner get_output()   emits: "validated_output", "status", "error_log",
                                        "trace_id", "correlation_id",
                                        "node_history"
            Outer merge_output() reads: sub_result.get("validated_output"),
                                        sub_result.get("status")

        `error_log` is carried so the outer boundary can recover the closed-set
        refusal label a domain node recorded. It is projected through
        `input_guard.project_refusal`, which emits a label only when it is a member
        of the known set — the text itself never reaches the caller.
        """
        return {
            "validated_output": state.get("validated_output"),
            "status": state.get("status"),
            "error_log": state.get("error_log", []),
            "trace_id": state.get("trace_id"),
            "correlation_id": state.get("correlation_id"),
            "node_history": state.get("node_history", []),
        }
