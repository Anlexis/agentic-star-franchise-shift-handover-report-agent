"""The output boundary and the error envelope.

`AgentBaseGraph.get_output` returns `state["formatted_output"] or
state["result"]`, and it does so on error status too. Two properties follow, and
both are asserted here separately, because a test that checked only one of them
would keep passing through the removal of the other:

  1. a refusal notice must be TRUTHY, or the `or` falls back onto `result`;
  2. `result` must be EMPTY, or the fallback has the un-gated document to serve.

The assertions are deliberately split that way so the mutant table means
something: drop the notice and `test_refusal_envelope_states_a_closed_set_reason`
fails; drop the clearing and `test_refusal_envelope_carries_no_document_text`
fails. A single assertion covering both would be satisfied by either guard alone
and would make each of them unfalsifiable.

There is one more thing to state plainly. Before this change nothing ever wrote a
truthy `result` on an error path, so the boundary leaked nothing on the day it was
measured — it was contained VACUOUSLY, one field away from leaking, not contained
by design. The tests below pin the design.
"""

import pytest

from framework.schemas.agent_status import AgentStatus
from src.graph.graph import ShiftHandoverGraphNode
from src.nodes.post_process_node import PostProcessNode
from src.nodes.response_validate_node import ResponseValidateNode, security_gate_output
from src.services import input_guard as guard
from src.services.report_format import OUTPUT_BEARING_FIELDS, REFUSAL_TITLE
from tests.fixtures import DB_URI, GITLAB_PAT, GITLAB_PAT_PREFIX

_DOCUMENT = "申し送り書\n店舗ID  : LAWSON-7-001\n売上合計: 150,000円"
_SUMMARY = "【日本語要約】\n店舗: LAWSON-7-001"


@pytest.fixture(autouse=True)
def _mute_audit(monkeypatch):
    """The real audit sink needs a live backend; the events themselves are
    asserted in tests/unit/test_agent.py."""
    import src.nodes.post_process_node as post_process
    import src.nodes.response_validate_node as response_validate

    for module in (response_validate, post_process):
        monkeypatch.setattr(module, "emit_trace_event", lambda *a, **k: None)


def _envelope(delta: dict) -> object:
    """What `get_output` would project from a state carrying this delta."""
    return delta.get("formatted_output") or delta.get("result")


# ── The scan itself ───────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "secret",
    [
        "password=hunter2",
        "api_key: abcd1234efgh",
        "Authorization: Basic YWJjOmRlZg==",
        "AKIAIOSFODNN7EXAMPLE",
        "sk_live_" + "51H8xKzABCDEFGHIJKLMNOPQRS",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abcdefghijkl",
        DB_URI,
        GITLAB_PAT,
    ],
)
def test_every_credential_shape_is_caught_at_the_boundary(secret: str) -> None:
    """The union, exercised at the boundary rather than only in the guard.

    The entry screen refuses most of these before the graph runs, which means an
    end-to-end probe cannot tell whether this boundary works. That is exactly the
    masked-leak shape, so the boundary is driven directly here.
    """
    assert security_gate_output(f"{_DOCUMENT}\n{secret}") == guard.REASON_CREDENTIAL


def test_a_clean_document_passes_the_boundary() -> None:
    assert security_gate_output(f"{_DOCUMENT}\n\n{_SUMMARY}") is None


# ── Containment at the boundary node ──────────────────────────────────────────


def _violating_state() -> dict:
    return {
        "shift_report": f"{_DOCUMENT}\nCI token {GITLAB_PAT}",
        "bilingual_summary": _SUMMARY,
        "error_log": [],
    }


def test_violation_returns_error_status() -> None:
    result = ResponseValidateNode().execute(_violating_state())
    assert result["status"] == AgentStatus.ERROR


def test_violation_withholds_the_document() -> None:
    """Raising, or returning ERROR with the fields still set, is not containment."""
    result = ResponseValidateNode().execute(_violating_state())
    assert not result.get("validated_output")
    for field in OUTPUT_BEARING_FIELDS:
        # Present AND empty: partial deltas are merged, so an omitted key would
        # leave the previous value in place.
        assert field in result, f"{field} must be cleared explicitly, not omitted"
        assert not result[field]


def test_violation_envelope_carries_no_document_text() -> None:
    result = ResponseValidateNode().execute(_violating_state())
    envelope = _envelope(result)
    assert envelope
    assert "LAWSON-7-001" not in envelope
    assert GITLAB_PAT_PREFIX not in envelope
    assert "申し送り書" not in envelope


def test_violation_envelope_states_a_closed_set_reason() -> None:
    result = ResponseValidateNode().execute(_violating_state())
    envelope = _envelope(result)
    assert REFUSAL_TITLE in envelope
    assert guard.REASON_CREDENTIAL in envelope


def test_violation_error_log_is_labels_not_text() -> None:
    """error_log is not projected today; it is kept closed-set anyway.

    It carries node-authored text and, wherever a node interpolates a caught
    exception, an upstream message body — so truncation or credential-only
    redaction would not be a closed error contract if it ever were projected.
    """
    result = ResponseValidateNode().execute(_violating_state())
    joined = " ".join(result["error_log"])
    assert guard.REASON_CREDENTIAL in joined
    assert GITLAB_PAT_PREFIX not in joined
    assert "Traceback" not in joined
    assert "src/" not in joined
    assert "申し送り書" not in joined


def test_empty_inner_output_is_refused_not_reported_as_success() -> None:
    result = ResponseValidateNode().execute({"shift_report": "", "bilingual_summary": "", "error_log": []})
    assert result["status"] == AgentStatus.ERROR
    assert _envelope(result)


# ── Containment at the subgraph boundary ──────────────────────────────────────


class _Error(Exception):
    def __init__(self, error_log):
        super().__init__("inner failed")
        self.error_log = error_log


def test_subgraph_error_is_contained_with_a_reason() -> None:
    """Every inner failure reaches the caller as a labelled refusal.

    With the framework's "propagate" strategy the node wrapper swallowed the
    failure and the caller received `output: None` with no reason anywhere.
    """
    delta = ShiftHandoverGraphNode().on_subgraph_error(
        {}, _Error(["InputParseNode: not_a_finite_number (waste_items[0].quantity_kg)"])
    )
    envelope = _envelope(delta)
    assert delta["status"] == AgentStatus.ERROR
    assert guard.REASON_NOT_FINITE in envelope
    assert "waste_items[0].quantity_kg" in envelope


def test_subgraph_error_never_re_emits_exception_text() -> None:
    """The framework default formats the exception into error_log as free text."""
    delta = ShiftHandoverGraphNode().on_subgraph_error(
        {}, _Error(['Traceback: ValueError("password=hunter2" at /app/src/nodes/x.py:12)'])
    )
    envelope = _envelope(delta)
    assert "password=hunter2" not in envelope
    assert "Traceback" not in envelope
    assert "/app/src" not in envelope
    assert guard.REASON_UPSTREAM in envelope


def test_merge_output_never_publishes_a_result_on_a_non_success_status() -> None:
    """`result` is the field the envelope falls back to when formatted_output is
    falsy, so a truthy result on a non-success run is the leak that fallback
    exists to produce."""
    delta = ShiftHandoverGraphNode().merge_output(
        {}, {"status": AgentStatus.ERROR.value, "validated_output": _DOCUMENT, "error_log": []}
    )
    assert not delta.get("result")
    assert "LAWSON-7-001" not in (_envelope(delta) or "")


def test_merge_output_publishes_the_document_on_success() -> None:
    delta = ShiftHandoverGraphNode().merge_output(
        {}, {"status": AgentStatus.SUCCESS.value, "validated_output": _DOCUMENT}
    )
    assert delta["result"] == _DOCUMENT


# ── The presentation step ─────────────────────────────────────────────────────


def test_post_process_presents_the_document() -> None:
    result = PostProcessNode().execute({"validated_output": _DOCUMENT})
    assert result["status"] == AgentStatus.SUCCESS
    assert result["formatted_output"] == _DOCUMENT


def test_post_process_refuses_to_report_an_empty_success() -> None:
    """An empty formatted_output re-reads `result`, and a success envelope with no
    document is a failure the caller cannot detect."""
    result = PostProcessNode().execute({"validated_output": "", "result": "", "error_log": []})
    assert result["status"] == AgentStatus.ERROR
    assert _envelope(result)
