"""AgentCore Platform v1.0"""

# Node contract:
#  - Extend FunctionNode; implement execute(state, config=None) -> dict
#  - Return ONLY the fields this node changes (never full state)
#  - Return AgentStatus enum constants — never plain strings
#  - Never import from mediator/, api/, or other agents
#
# RET-C2-256 — WasteFormatNode
# Inner DomainWorkflowGraph node 3: express the shift's food waste in the
# regulatory log format required by the Act on Promotion of Food Loss Reduction
# (食品ロス削減推進法), FY2026 reporting.
#
# Input state keys:
#   shift_data: dict — normalised payload (waste_items, store_id, shift_date)
#
# Output state keys (partial dict returned):
#   waste_log: dict — the regulatory log
#   status: AgentStatus
#
# waste_log shape:
#   store_id, report_date, shift_type,
#   entries: [{item_name, quantity_kg, category, disposal_method, regulatory_code}],
#   total_kg, regulation
#
# This log is a regulatory record, which raises the bar on two things a purely
# internal document could be relaxed about:
#   - every quantity is proved finite before it is summed, so the total cannot
#     come out as "nan" or "inf" in a filing;
#   - item names are caller free text and are neutralised before they enter the
#     record, so nothing in it can be made to read as a heading or a separate
#     entry.
#
# Security notes:
#   Trust: ANONYMOUS — inner node.
#   Audit: emit_trace_event on completion.

import logging
from typing import Any, ClassVar, Dict, List, Optional

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from shared.utils.audit_logger import emit_trace_event
from src.nodes.input_parse_node import BOUNDS, MAX_ITEM_NAME_CHARS
from src.services.input_guard import finite_in_range
from src.services.report_format import render_safe

logger = logging.getLogger(__name__)

# ── Regulatory mapping ────────────────────────────────────────────────────────
# Category-to-code mapping for the FY2026 reporting format.
_REGULATORY_CODE_MAP: Dict[str, str] = {
    "perishable": "SL-F01",  # fresh produce, meat, fish
    "prepared": "SL-F02",  # prepared foods, bento, salads
    "beverage": "SL-B01",  # bottled and canned beverages
    "bakery": "SL-F03",  # bread, pastries
    "dairy": "SL-F04",  # milk, yogurt, cheese
    "other": "SL-X99",  # uncategorised
}
REGULATION_LABEL = "Food Loss Reduction Act FY2026"

_VALID_DISPOSAL_METHODS = frozenset({"compost", "incineration", "donation", "animal_feed", "other"})
_DEFAULT_CATEGORY = "other"
_DEFAULT_DISPOSAL = "incineration"

# A quantity that cannot be read as finite. The entry is still recorded — omitting
# it would understate the filing — but it contributes nothing to the total and is
# marked, so an unreadable value can never be mistaken for zero waste.
UNREADABLE_QUANTITY_LABEL = "unreadable"


def _normalise_category(raw: Any) -> str:
    """Map free-text category to one of the closed regulatory categories."""
    text = str(raw).strip().lower()
    if text in _REGULATORY_CODE_MAP:
        return text
    if any(kw in text for kw in ("bread", "pastry", "baked")):
        return "bakery"
    if any(kw in text for kw in ("milk", "dairy", "cheese", "yogurt")):
        return "dairy"
    if any(kw in text for kw in ("drink", "beverage", "juice", "coffee", "tea", "water")):
        return "beverage"
    if any(kw in text for kw in ("fresh", "produce", "meat", "fish", "seafood", "vegetable", "fruit")):
        return "perishable"
    if any(kw in text for kw in ("prepared", "bento", "salad", "cooked", "meal", "rice", "sandwich")):
        return "prepared"
    return _DEFAULT_CATEGORY


def _normalise_disposal(raw: Any) -> str:
    """Map a free-text disposal method to one of the closed canonical values."""
    text = str(raw).strip().lower().replace(" ", "_")
    if text in _VALID_DISPOSAL_METHODS:
        return text
    if "compost" in text or "organic" in text:
        return "compost"
    if "donat" in text or "food bank" in text:
        return "donation"
    if "animal" in text or "feed" in text:
        return "animal_feed"
    return _DEFAULT_DISPOSAL


class WasteFormatNode(FunctionNode):
    """Build the regulatory food-waste log for the shift.

    Third node in DomainWorkflowGraph. Each entry carries a regulatory code
    derived from its category, and the total is summed from the proved-finite
    quantities only.
    """

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    def execute(self, state: Dict[str, Any], config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        shift_data: Dict[str, Any] = state.get("shift_data") or {}

        store_id: str = shift_data.get("store_id") or str(state.get("store_id") or "")
        report_date: str = shift_data.get("shift_date") or str(state.get("shift_date") or "")
        shift_type: str = shift_data.get("shift_type") or str(state.get("shift_type") or "")
        raw_waste_items: List[Any] = shift_data.get("waste_items") or []

        low, high = BOUNDS["quantity_kg"]
        entries: List[Dict[str, Any]] = []
        total_kg = 0.0
        unreadable = 0

        for item in raw_waste_items:
            if not isinstance(item, dict):
                continue
            quantity = finite_in_range(item.get("quantity_kg", 0), low, high)
            category = _normalise_category(item.get("category", ""))
            entry: Dict[str, Any] = {
                "item_name": render_safe(item.get("item_name", ""), MAX_ITEM_NAME_CHARS) or "Unnamed item",
                "quantity_kg": round(quantity, 3) if quantity is not None else UNREADABLE_QUANTITY_LABEL,
                "category": category,
                "disposal_method": _normalise_disposal(item.get("disposal_method", "")),
                "regulatory_code": _REGULATORY_CODE_MAP.get(category, "SL-X99"),
            }
            if quantity is None:
                unreadable += 1
            else:
                total_kg += quantity
            entries.append(entry)

        waste_log: Dict[str, Any] = {
            "store_id": store_id,
            "report_date": report_date,
            "shift_type": shift_type,
            "entries": entries,
            "total_kg": round(total_kg, 3),
            "unreadable_entries": unreadable,
            "regulation": REGULATION_LABEL,
        }

        logger.info(
            "WasteFormatNode: %d entries, total_kg=%.3f, unreadable=%d, store=%s date=%s",
            len(entries),
            total_kg,
            unreadable,
            store_id,
            report_date,
        )

        emit_trace_event(
            "waste_log_formatted",
            {
                "store_id": store_id,
                "report_date": report_date,
                "entry_count": len(entries),
                "unreadable_entries": unreadable,
                "total_kg": round(total_kg, 3),
                "regulation": REGULATION_LABEL,
            },
            state,
        )

        return {
            "waste_log": waste_log,
            "status": AgentStatus.SUCCESS,
        }
