"""AgentCore Platform v1.0"""

# Node contract:
#  - Extend FunctionNode; implement execute(state, config=None) -> dict
#  - Return ONLY the fields this node changes (never full state)
#  - Return AgentStatus enum constants — never plain strings
#  - Never import from mediator/, api/, or other agents
#
# RET-C2-256 — PostProcessNode
# Outer backbone node: present the finished handover document to the caller.
#
# Input state keys:
#   validated_output: str — the gated response from the inner graph
#   result:           str — the same text as merged by ShiftHandoverGraphNode
#
# Output state keys (partial dict returned):
#   formatted_output: str
#   status: AgentStatus
#
# Scope note, because it bounds what this node can be responsible for: the
# backbone routes `main → post_process` only on SUCCESS. Every error status routes
# `main → finalize`, so this node is NOT on the failure path and cannot be the
# place containment lives. That is why the refusal envelope is built in
# ShiftHandoverGraphNode and in the domain nodes themselves.
#
# What this node does own is the other half of the same rule: a run that reaches
# here with nothing to show must not report success with an empty body.
# `AgentBaseGraph.get_output` returns `formatted_output or result`, so an empty
# formatted_output silently re-reads `result`; and a success envelope with no
# document is a failure the caller cannot detect.
#
# Security notes:
#   The response already passed the output boundary in ResponseValidateNode; this
#   node adds no text of its own and re-scans nothing.
#   Audit: emit_trace_event on both paths.

import logging
from typing import Any, ClassVar, Dict, List, Optional

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from shared.utils.audit_logger import emit_trace_event
from src.services import input_guard as guard
from src.services.report_format import contained_refusal

logger = logging.getLogger(__name__)


class PostProcessNode(FunctionNode):
    """Present the finished handover document.

    Reads validated_output, set by ResponseValidateNode in the inner graph, and
    falls back to result — the same text, merged by ShiftHandoverGraphNode. If
    neither carries anything the run is reported as an error rather than as an
    empty success.

    Trust level: ANONYMOUS — a downstream backbone node; the external gate is
    PreProcessNode.
    """

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    def execute(self, state: Dict[str, Any], config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        error_log: List[str] = list(state.get("error_log") or [])
        document: str = state.get("validated_output") or state.get("result") or ""

        if not document:
            logger.error("PostProcessNode: reached the presentation step with no document")
            emit_trace_event(
                "post_process_empty",
                {"reason": guard.REASON_MISSING, "location": "validated_output"},
                state,
            )
            delta: Dict[str, Any] = contained_refusal(guard.REASON_MISSING, "validated_output")
            delta["status"] = AgentStatus.ERROR
            delta["error_log"] = error_log + [f"PostProcessNode: {guard.REASON_MISSING} (validated_output)"]
            return delta

        emit_trace_event(
            "post_process_complete",
            {"output_length": len(document), "status": "success"},
            state,
        )

        return {
            "formatted_output": document,
            "status": AgentStatus.SUCCESS,
        }
