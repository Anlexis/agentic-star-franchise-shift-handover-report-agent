"""AgentCore Platform v1.0"""

# Node contract:
#  - Extend FunctionNode; implement execute(state, config=None) -> dict
#  - Return ONLY the fields this node changes (never full state)
#  - Return AgentStatus enum constants — never plain strings
#  - Never import from mediator/, api/, or other agents
#
# RET-C2-256 — ResponseValidateNode
# Inner DomainWorkflowGraph node 6 (final): the output boundary. Assembles the
# handover document and the bilingual summary into one response and holds it to
# the invariant this template states — nothing credential-shaped leaves here.
#
# Input state keys:
#   shift_report, bilingual_summary
#
# Output state keys (partial dict returned):
#   validated_output: str — on success
#   on violation: status=ERROR, a closed-set reason, and every output-bearing
#   field emptied
#
# The invariant, and why it is enforced the way it is:
#
#   The scan is the UNION of the framework's own credential detector, this
#   template's assignment patterns, and a forge/platform token pattern. Each
#   catches shapes the others miss — the table in src/services/input_guard.py has
#   the measured results — and the union is the only composition that is not a
#   narrowing of one of them. A scan narrower than the framework's is worse than
#   useless here: the framework raises on the value anyway, but it raises INSIDE
#   the node wrapper, which discards this node's delta and with it any clearing
#   this node did.
#
#   On violation the node returns ERROR and EMPTIES the output-bearing fields.
#   Raising, or returning ERROR while leaving them set, is not containment:
#   `AgentBaseGraph.get_output` returns `formatted_output or result`, and it does
#   so on error status too. Because a violation routes the backbone straight to
#   finalize — post_process never runs on an error path — this node and the
#   graph node above it are the only places the caller-visible envelope can be
#   set at all.
#
# Security notes:
#   Trust: ANONYMOUS — inner node.
#   Audit: emit_trace_event on the pass path and on every violation, with a
#     closed-set reason. The pattern that matched is never named in the caller's
#     error: a pattern source is node-authored text, and the caller-visible error
#     contract is labels only.

import logging
from typing import Any, ClassVar, Dict, List, Optional

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from shared.utils.audit_logger import emit_trace_event
from src.services import input_guard as guard
from src.services.report_format import contained_refusal

logger = logging.getLogger(__name__)

# Location labels for the boundary's own findings. Closed set, like every other
# reason this template emits.
LOCATION_REPORT = "shift_report"
LOCATION_SUMMARY = "bilingual_summary"
LOCATION_OUTPUT = "validated_output"


def security_gate_output(output: str) -> Optional[str]:
    """The output invariant. Returns a closed-set reason, or None when clean.

    A module-level helper called directly from `execute()`, not an
    `_extra_security_gate_output()` instance hook — the SDK auto-wraps those and
    passes a None working state.
    """
    if guard.screen_credentials(output):
        return guard.REASON_CREDENTIAL
    return None


class ResponseValidateNode(FunctionNode):
    """The output boundary — final inner domain node.

    Assembles the response from the Japanese handover document and the bilingual
    summary, then holds it to the credential invariant. On a violation the
    response is withheld: the node returns ERROR, empties every output-bearing
    field, and the caller receives a closed-set notice rather than a partially
    gated document.
    """

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    def execute(self, state: Dict[str, Any], config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        error_log: List[str] = list(state.get("error_log") or [])
        shift_report: str = state.get("shift_report") or ""
        bilingual_summary: str = state.get("bilingual_summary") or ""

        parts = [part for part in (shift_report, bilingual_summary) if part]
        if not parts:
            return self._withhold(guard.REASON_MISSING, LOCATION_OUTPUT, error_log, state)

        combined_output = "\n\n".join(parts)

        reason = security_gate_output(combined_output)
        if reason:
            # Name the section for the operator's audit trail, not for the caller.
            location = LOCATION_REPORT if security_gate_output(shift_report) else LOCATION_SUMMARY
            return self._withhold(reason, location, error_log, state)

        logger.info("ResponseValidateNode: output cleared the boundary, length=%d", len(combined_output))

        emit_trace_event(
            "output_validated",
            {
                "output_length": len(combined_output),
                "has_shift_report": bool(shift_report),
                "has_bilingual_summary": bool(bilingual_summary),
                "credential_scan": "pass",
            },
            state,
        )

        return {
            "validated_output": combined_output,
            "status": AgentStatus.SUCCESS,
        }

    @staticmethod
    def _withhold(reason: str, location: str, error_log: List[str], state: Dict[str, Any]) -> Dict[str, Any]:
        """Withhold the response: ERROR, closed-set reason, nothing left to serve."""
        logger.error("ResponseValidateNode: output withheld (%s at %s)", reason, location)
        emit_trace_event(
            "output_withheld",
            {"reason": reason, "location": location},
            state,
        )
        delta: Dict[str, Any] = contained_refusal(reason, location)
        delta["status"] = AgentStatus.ERROR
        delta["error_log"] = error_log + [f"ResponseValidateNode: {reason} ({location})"]
        return delta
