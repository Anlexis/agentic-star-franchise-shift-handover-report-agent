"""AgentCore Platform v1.0"""

# Node contract:
#  - Extend FunctionNode; implement execute(state, config=None) -> dict
#  - Return ONLY the fields this node changes (never full state)
#  - Return AgentStatus enum constants — never plain strings
#  - Read input_context via state.get("input_context", {}) — read-only
#  - Never import from mediator/, api/, or other agents
#
# RET-C2-256 — PreProcessNode
# Outer backbone node: the trust gate and the input gate for the whole agent.
# Validates the incoming shift handover request before the inner
# DomainWorkflowGraph is invoked.
#
# Input state keys:
#   user_input: str — the shift payload, JSON-encoded
#
# Output state keys (partial dict returned):
#   validated_input: str — the payload, unchanged, once it has passed every screen
#   store_id / shift_date / shift_type: str — metadata hints for downstream nodes
#   status: AgentStatus — SUCCESS or ERROR
#   error_log: list[str] — closed-set refusal labels on failure
#   formatted_output + cleared document fields — on failure only; see below
#
# Security notes:
#   Trust: VERIFIED_EXTERNAL — this is the outermost caller gate.
#   Input: screens run BEFORE validated_input is written — type and size guard,
#     then the shared screens in src/services/input_guard.py, which cover
#     chat-template control markers, high-confidence injection directives,
#     credential shapes (the union of three detectors) and personal-data shapes,
#     raw and markup-stripped, depth-first over the parsed payload including keys.
#     The screens are module-level helpers invoked directly from execute(), not an
#     `_extra_*` FunctionNode hook — the SDK auto-wraps those and passes a None
#     working state.
#   Containment: a refusal routes straight to finalize, so this node owns the
#     caller-visible envelope for everything it rejects. It returns a truthy
#     closed-set notice and clears every output-bearing field; a falsy one would
#     re-open `get_output`'s fallback onto `result`.
#   Audit: emit_trace_event on every rejection path and on the success path.

import json
import logging
from typing import Any, ClassVar, Dict, List, Optional

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from shared.utils.audit_logger import emit_trace_event
from src.services import input_guard as guard
from src.services.report_format import contained_refusal

logger = logging.getLogger(__name__)

# Upper bound on the serialised payload. The HTTP adapter applies the same ceiling
# in front of the graph; this one covers every other way in, including the
# platform gateway calling invoke() directly.
MAX_INPUT_BYTES = 256 * 1024

# Metadata hints this node lifts out of the payload for downstream nodes. Each one
# renders into the report, so each is held to the inert identifier shape here
# rather than trusted and rendered later.
_HINT_FIELDS = ("store_id", "shift_type")


def _refuse(reason: str, location: str, error_log: List[str], state: Dict[str, Any]) -> Dict[str, Any]:
    """Build the ERROR delta for a refused request.

    One helper so every refusal in this node carries the same closed-set contract:
    a labelled reason in the log, a truthy notice in the envelope, and nothing
    generated left anywhere the envelope can fall back onto.
    """
    emit_trace_event(
        "pre_process_rejected",
        {"reason": reason, "location": location or "value"},
        state,
    )
    delta: Dict[str, Any] = contained_refusal(reason, location)
    delta["status"] = AgentStatus.ERROR
    delta["error_log"] = error_log + [f"PreProcessNode: {reason} ({location or 'value'})"]
    return delta


class PreProcessNode(FunctionNode):
    """Trust and input gate for RET-C2-256.

    Screens the raw user_input and, only once it is clean, extracts lightweight
    metadata for the inner graph. Structural parsing stays in InputParseNode.

    Trust level: VERIFIED_EXTERNAL — this is the backbone caller gate, and it is
    the level the manifest declares. All real callers arrive here first.
    """

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.VERIFIED_EXTERNAL

    def execute(self, state: Dict[str, Any], config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        error_log: List[str] = list(state.get("error_log") or [])
        user_input: Any = state.get("user_input", "")

        if not isinstance(user_input, str):
            return _refuse(guard.REASON_WRONG_TYPE, "user_input", error_log, state)

        if not user_input.strip():
            return _refuse(guard.REASON_MISSING, "user_input", error_log, state)

        if len(user_input.encode("utf-8")) > MAX_INPUT_BYTES:
            return _refuse(guard.REASON_TOO_LONG, "user_input", error_log, state)

        candidate = user_input.strip()

        # The raw text, then the parsed structure with keys included — the same
        # composition the HTTP adapter applies, taken from one place so the two
        # cannot drift into screening different things.
        refusal = guard.screen_request(candidate)
        if refusal:
            return _refuse(refusal[0], refusal[1], error_log, state)

        parsed: Any = None
        try:
            parsed = json.loads(candidate)
        except (json.JSONDecodeError, TypeError, ValueError):
            # Not JSON. InputParseNode owns the structural verdict and refuses with
            # its own closed-set reason; nothing is committed here that depends on
            # the payload being an object.
            logger.debug("PreProcessNode: payload is not JSON; deferring the verdict to InputParseNode")

        # ── Input is clean — commit validated_input ───────────────────────────
        result: Dict[str, Any] = {
            "validated_input": candidate,
            "status": AgentStatus.SUCCESS,
        }

        # ── Metadata hints, held to the inert shape ───────────────────────────
        hints: Dict[str, str] = {}
        if isinstance(parsed, dict):
            for field in _HINT_FIELDS:
                normalised = guard.normalise_identifier(parsed.get(field))
                if normalised is not None:
                    hints[field] = normalised
            shift_date = parsed.get("shift_date")
            if isinstance(shift_date, str) and guard.normalise_identifier(shift_date):
                hints["shift_date"] = shift_date.strip()
        result.update(hints)

        logger.info(
            "PreProcessNode: validated input len=%d hints=%s",
            len(candidate),
            sorted(hints),
        )

        emit_trace_event(
            "pre_process_validated",
            {
                "input_length": len(candidate),
                "hint_fields": sorted(hints),
                "payload_is_object": isinstance(parsed, dict),
            },
            state,
        )
        return result
