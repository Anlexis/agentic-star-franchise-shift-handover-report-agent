"""AgentCore Platform v1.0"""

# Node contract:
#  - Extend FunctionNode; implement execute(state, config=None) -> dict
#  - Return ONLY the fields this node changes (never full state)
#  - Return AgentStatus enum constants — never plain strings
#  - Never import from mediator/, api/, or other agents
#
# RET-C2-256 — InputParseNode
# Inner DomainWorkflowGraph node 1: parse the shift handover payload and hold it
# to an explicit contract before any downstream node computes from it.
#
# Input state keys:
#   validated_input: str — the payload, JSON-encoded (falls back to user_input
#     when the inner graph is invoked on its own)
#
# Output state keys (partial dict returned):
#   shift_data: dict — the payload, normalised: every number finite and in range,
#     every list within its entry cap, every string within its length cap
#   store_id / shift_date / shift_type: str
#   status / error_log / formatted_output + cleared document fields
#
# Payload contract (see docs/03_test_spec.md for the authored schema):
#   store_id    str   inert identifier, <= 32 chars, e.g. "LAWSON-7-001"
#   shift_date  str   YYYY-MM-DD
#   shift_type  str   morning | afternoon | night (a _shift suffix is accepted)
#   staff       list  <= 50 x {name?, staff_ref?, role, hours_worked}
#   sales       dict  {total_yen, transaction_count, vs_target_pct}
#   incidents   list  <= 50 x {type, severity, description, time}
#   waste_items list  <= 200 x {item_name, quantity_kg, category, disposal_method}
#
# Every caller-controlled number goes through the shared finite + bounded parser
# and FAILS CLOSED. That is not defensive style: driven through the real graph, a
# NaN `quantity_kg` reported "nan kg" in the regulatory waste log AND silently
# suppressed the overrun anomaly, because every comparison against NaN is False —
# a fail-open on the exact decision this pipeline exists to make. Python's json
# parses bare NaN and Infinity straight out of a request body.
#
# Security notes:
#   Trust: ANONYMOUS — inner graph node; the external gate is PreProcessNode.
#   Audit: emit_trace_event on the accept path and on every refusal.

import json
import logging
import re
from typing import Any, ClassVar, Dict, List, Optional, Tuple

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from shared.utils.audit_logger import emit_trace_event
from src.services import input_guard as guard
from src.services.report_format import contained_refusal

logger = logging.getLogger(__name__)

# ── Contract constants ────────────────────────────────────────────────────────

_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_REQUIRED_KEYS = ("store_id", "shift_date", "shift_type", "staff", "sales", "waste_items")
_CANONICAL_SHIFTS = frozenset({"morning", "afternoon", "night"})

# Entry caps. Without them 2,000 waste entries rendered a 474 KB report — a
# structural denial of service that needs no malformed value at all.
MAX_STAFF = 50
MAX_INCIDENTS = 50
MAX_WASTE_ITEMS = 200

# Length caps for free text that reaches the document. The renderer bounds what it
# prints as well; this is the contract, that is the last line of defence.
MAX_NAME_CHARS = 64
MAX_ROLE_CHARS = 40
MAX_ITEM_NAME_CHARS = 120
MAX_DESCRIPTION_CHARS = 200
MAX_TIME_CHARS = 32
MAX_CATEGORY_CHARS = 40

# Numeric bounds, per field. A value outside these is a caller mistake, and the
# request is refused naming the field rather than degraded silently.
BOUNDS: Dict[str, Tuple[float, float]] = {
    "hours_worked": (0.0, 24.0),
    "total_yen": (-1e11, 1e12),
    "transaction_count": (0.0, 1e7),
    "vs_target_pct": (-100.0, 1e4),
    "quantity_kg": (0.0, 1e4),
}

_SEVERITIES = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})


class _Refusal(Exception):
    """Internal signal: a closed-set reason plus an inert field location."""

    def __init__(self, reason: str, location: str) -> None:
        super().__init__(reason)
        self.reason = reason
        self.location = location


def _require_text(value: Any, location: str, limit: int, *, allow_empty: bool = False) -> str:
    """A caller string, type- and length-checked. Never echoed back on refusal."""
    if value is None and allow_empty:
        return ""
    if not isinstance(value, str):
        raise _Refusal(guard.REASON_WRONG_TYPE, location)
    text = value.strip()
    if not text and not allow_empty:
        raise _Refusal(guard.REASON_MISSING, location)
    if len(text) > limit:
        raise _Refusal(guard.REASON_TOO_LONG, location)
    return text


def _require_number(value: Any, field: str, location: str, *, default: Optional[float] = None) -> float:
    """A caller number, finite and inside this field's declared bounds.

    Fails CLOSED. `default` is used only when the key is absent altogether — a
    present-but-unusable value is a refusal, never a silent substitution.
    """
    if value is None and default is not None:
        return default
    low, high = BOUNDS[field]
    parsed = guard.finite_in_range(value, low, high)
    if parsed is None:
        # Distinguish the two so the caller can tell a typo from a bound breach,
        # without echoing the value.
        try:
            is_numeric = not isinstance(value, bool) and float(value) == float(value)
        except (TypeError, ValueError):
            is_numeric = False
        raise _Refusal(guard.REASON_OUT_OF_RANGE if is_numeric else guard.REASON_NOT_FINITE, location)
    return parsed


def _require_list(value: Any, location: str, cap: int) -> List[Any]:
    if not isinstance(value, list):
        raise _Refusal(guard.REASON_WRONG_TYPE, location)
    if len(value) > cap:
        raise _Refusal(guard.REASON_TOO_MANY, location)
    return value


def _parse_staff(raw: Any) -> List[Dict[str, Any]]:
    """Normalise the staff roster.

    `staff_ref` is the field that reaches the document; it is held to the inert
    identifier shape. `name` is accepted for compatibility and deliberately NOT
    carried forward — see the renderer for why a personal name cannot survive the
    round trip intact anyway.
    """
    entries = _require_list(raw, "staff", MAX_STAFF)
    out: List[Dict[str, Any]] = []
    for index, entry in enumerate(entries):
        here = f"staff[{index}]"
        if not isinstance(entry, dict):
            raise _Refusal(guard.REASON_WRONG_TYPE, here)
        ref_raw = entry.get("staff_ref")
        staff_ref = guard.normalise_identifier(ref_raw) if ref_raw is not None else None
        if ref_raw is not None and staff_ref is None:
            raise _Refusal(guard.REASON_INVALID_IDENTIFIER, f"{here}.staff_ref")
        # `name` is length-checked so an oversized payload is still refused, then
        # dropped.
        _require_text(entry.get("name"), f"{here}.name", MAX_NAME_CHARS, allow_empty=True)
        out.append(
            {
                "staff_ref": staff_ref or "",
                "role": _require_text(entry.get("role"), f"{here}.role", MAX_ROLE_CHARS, allow_empty=True),
                "hours_worked": _require_number(
                    entry.get("hours_worked"), "hours_worked", f"{here}.hours_worked", default=0.0
                ),
            }
        )
    return out


def _parse_sales(raw: Any) -> Dict[str, Any]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise _Refusal(guard.REASON_WRONG_TYPE, "sales")
    sales: Dict[str, Any] = {}
    for key in ("total_yen", "transaction_count", "vs_target_pct"):
        if raw.get(key) is None:
            continue
        sales[key] = _require_number(raw.get(key), key, f"sales.{key}")
    return sales


def _parse_incidents(raw: Any) -> List[Dict[str, Any]]:
    entries = _require_list(raw if raw is not None else [], "incidents", MAX_INCIDENTS)
    out: List[Dict[str, Any]] = []
    for index, entry in enumerate(entries):
        here = f"incidents[{index}]"
        if not isinstance(entry, dict):
            raise _Refusal(guard.REASON_WRONG_TYPE, here)
        severity = _require_text(entry.get("severity"), f"{here}.severity", 16, allow_empty=True).upper()
        if severity and severity not in _SEVERITIES:
            raise _Refusal(guard.REASON_INVALID_IDENTIFIER, f"{here}.severity")
        out.append(
            {
                "type": _require_text(entry.get("type"), f"{here}.type", MAX_CATEGORY_CHARS, allow_empty=True),
                "severity": severity or "MEDIUM",
                "description": _require_text(
                    entry.get("description"), f"{here}.description", MAX_DESCRIPTION_CHARS, allow_empty=True
                ),
                "time": _require_text(entry.get("time"), f"{here}.time", MAX_TIME_CHARS, allow_empty=True),
            }
        )
    return out


def _parse_waste_items(raw: Any) -> List[Dict[str, Any]]:
    entries = _require_list(raw, "waste_items", MAX_WASTE_ITEMS)
    out: List[Dict[str, Any]] = []
    for index, entry in enumerate(entries):
        here = f"waste_items[{index}]"
        if not isinstance(entry, dict):
            raise _Refusal(guard.REASON_WRONG_TYPE, here)
        out.append(
            {
                "item_name": _require_text(
                    entry.get("item_name"), f"{here}.item_name", MAX_ITEM_NAME_CHARS, allow_empty=True
                ),
                "quantity_kg": _require_number(
                    entry.get("quantity_kg"), "quantity_kg", f"{here}.quantity_kg", default=0.0
                ),
                "category": _require_text(
                    entry.get("category"), f"{here}.category", MAX_CATEGORY_CHARS, allow_empty=True
                ),
                "disposal_method": _require_text(
                    entry.get("disposal_method"), f"{here}.disposal_method", MAX_CATEGORY_CHARS, allow_empty=True
                ),
            }
        )
    return out


class InputParseNode(FunctionNode):
    """Parse and validate the shift handover payload.

    First node in DomainWorkflowGraph. Converts validated_input into a normalised
    shift_data mapping and enforces the payload contract before any downstream
    node computes from it. Refusals name a field and a closed-set reason and never
    quote the rejected value.
    """

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    def execute(self, state: Dict[str, Any], config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        error_log: List[str] = list(state.get("error_log") or [])
        # The inner graph starts from `user_input` when it is invoked on its own;
        # `validated_input` is set only when the outer PreProcessNode ran first.
        raw = state.get("validated_input") or state.get("user_input", "")

        try:
            payload = self._deserialise(raw)
            shift_data = self._build(payload)
        except _Refusal as refusal:
            return self._refuse(refusal.reason, refusal.location, error_log, state)

        logger.info(
            "InputParseNode: parsed store=%s date=%s shift=%s staff=%d waste_items=%d incidents=%d",
            shift_data["store_id"],
            shift_data["shift_date"],
            shift_data["shift_type"],
            len(shift_data["staff"]),
            len(shift_data["waste_items"]),
            len(shift_data["incidents"]),
        )

        emit_trace_event(
            "shift_data_parsed",
            {
                "store_id": shift_data["store_id"],
                "shift_date": shift_data["shift_date"],
                "shift_type": shift_data["shift_type"],
                "staff_count": len(shift_data["staff"]),
                "waste_item_count": len(shift_data["waste_items"]),
                "incident_count": len(shift_data["incidents"]),
            },
            state,
        )

        return {
            "shift_data": shift_data,
            "store_id": shift_data["store_id"],
            "shift_date": shift_data["shift_date"],
            "shift_type": shift_data["shift_type"],
            "status": AgentStatus.SUCCESS,
            "error_log": error_log,
        }

    # ── helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _deserialise(raw: Any) -> Dict[str, Any]:
        if isinstance(raw, dict):
            return raw
        if not isinstance(raw, str):
            raise _Refusal(guard.REASON_WRONG_TYPE, "validated_input")
        try:
            parsed = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            # The decoder's message quotes the offending input position and text;
            # the caller gets a category instead.
            raise _Refusal(guard.REASON_MALFORMED, "validated_input") from None
        if not isinstance(parsed, dict):
            raise _Refusal(guard.REASON_WRONG_TYPE, "validated_input")
        return parsed

    @staticmethod
    def _build(payload: Dict[str, Any]) -> Dict[str, Any]:
        missing = [key for key in _REQUIRED_KEYS if key not in payload]
        if missing:
            raise _Refusal(guard.REASON_MISSING, missing[0])

        store_id = guard.normalise_identifier(payload.get("store_id"))
        if store_id is None:
            raise _Refusal(guard.REASON_INVALID_IDENTIFIER, "store_id")

        shift_date = _require_text(payload.get("shift_date"), "shift_date", 10)
        if not _DATE_RE.match(shift_date):
            raise _Refusal(guard.REASON_INVALID_IDENTIFIER, "shift_date")

        shift_type = _require_text(payload.get("shift_type"), "shift_type", 32).lower()
        canonical = shift_type.replace("_shift", "")
        if canonical not in _CANONICAL_SHIFTS:
            raise _Refusal(guard.REASON_INVALID_IDENTIFIER, "shift_type")

        return {
            "store_id": store_id,
            "shift_date": shift_date,
            "shift_type": canonical,
            "staff": _parse_staff(payload.get("staff")),
            "sales": _parse_sales(payload.get("sales")),
            "incidents": _parse_incidents(payload.get("incidents")),
            "waste_items": _parse_waste_items(payload.get("waste_items")),
        }

    @staticmethod
    def _refuse(reason: str, location: str, error_log: List[str], state: Dict[str, Any]) -> Dict[str, Any]:
        emit_trace_event(
            "shift_data_rejected",
            {"reason": reason, "location": location},
            state,
        )
        delta: Dict[str, Any] = contained_refusal(reason, location)
        delta["status"] = AgentStatus.ERROR
        delta["error_log"] = error_log + [f"InputParseNode: {reason} ({location})"]
        return delta
