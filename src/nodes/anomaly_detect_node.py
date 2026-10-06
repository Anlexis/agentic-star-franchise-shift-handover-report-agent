"""AgentCore Platform v1.0"""

# Node contract:
#  - Extend FunctionNode; implement execute(state, config=None) -> dict
#  - Return ONLY the fields this node changes (never full state)
#  - Return AgentStatus enum constants — never plain strings
#  - Never import from mediator/, api/, or other agents
#
# RET-C2-256 — AnomalyDetectNode
# Inner DomainWorkflowGraph node 2: read the normalised shift_data and flag the
# operational conditions that need the next shift's or the manager's attention.
#
# Input state keys:
#   shift_data: dict — normalised payload from InputParseNode
#
# Output state keys (partial dict returned):
#   anomalies: list[dict] — {type, severity, description, source}
#   escalation_required: bool — any HIGH or CRITICAL finding
#   status: AgentStatus
#
# Conditions detected:
#   cooler_alarm     temperature or equipment incidents
#   understaffed     roster below the minimum
#   sales_shortfall  vs_target_pct below the shortfall threshold
#   incident_flag    any incident already reported HIGH or CRITICAL
#   waste_overrun    total waste above the threshold
#   unassessable     a number that could not be read as finite (see below)
#
# Every threshold comparison here is a decision this template exists to make, so
# none of them may be reached with a value that has not been proved finite.
# InputParseNode refuses such a payload outright; this node is reachable on its
# own (the inner graph can be invoked directly), so it fails CLOSED rather than
# repeating the comparison: an unreadable number raises an `unassessable` finding
# at HIGH instead of quietly answering "no anomaly". A NaN compares False against
# every threshold, which is silence that looks exactly like a clean shift.
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
from src.nodes.input_parse_node import BOUNDS
from src.services.input_guard import finite_in_range

logger = logging.getLogger(__name__)

# ── Thresholds ────────────────────────────────────────────────────────────────

_ESCALATION_SEVERITIES = frozenset({"HIGH", "CRITICAL"})
MIN_STAFF_COUNT = 1
SALES_SHORTFALL_PCT = -10.0
SALES_SHORTFALL_SEVERE_PCT = -20.0
WASTE_OVERRUN_KG = 20.0

_COOLER_INCIDENT_TYPES = frozenset({"cooler_alarm", "temperature_alert", "equipment_failure", "freezer_alarm"})


def _unassessable(location: str) -> Dict[str, Any]:
    """A finding raised when a number cannot be read as finite.

    Deliberately HIGH: the shift may well be fine, but this agent cannot say so,
    and "cannot say" must not be rendered as "nothing found".
    """
    return {
        "type": "unassessable",
        "severity": "HIGH",
        "description": f"Value could not be read as a finite number: {location}",
        "source": "validation",
    }


def _detect_from_incidents(incidents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Findings derived from the reported incidents."""
    anomalies: List[Dict[str, Any]] = []
    for incident in incidents:
        if not isinstance(incident, dict):
            continue
        incident_type = str(incident.get("type", "")).lower()
        severity = str(incident.get("severity", "MEDIUM")).upper()
        description = str(incident.get("description", ""))
        time = str(incident.get("time", ""))

        if incident_type in _COOLER_INCIDENT_TYPES:
            anomalies.append(
                {
                    "type": "cooler_alarm",
                    "severity": severity,
                    "description": description or f"Cooler or temperature incident at {time}",
                    "source": "incidents",
                }
            )
        elif severity in _ESCALATION_SEVERITIES:
            anomalies.append(
                {
                    "type": "incident_flag",
                    "severity": severity,
                    "description": description or f"High-severity incident at {time}",
                    "source": "incidents",
                }
            )
    return anomalies


def _detect_from_sales(sales: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Findings derived from the sales figures."""
    raw = sales.get("vs_target_pct")
    if raw is None:
        return []
    low, high = BOUNDS["vs_target_pct"]
    pct = finite_in_range(raw, low, high)
    if pct is None:
        return [_unassessable("sales.vs_target_pct")]
    if pct >= SALES_SHORTFALL_PCT:
        return []
    return [
        {
            "type": "sales_shortfall",
            "severity": "HIGH" if pct < SALES_SHORTFALL_SEVERE_PCT else "MEDIUM",
            "description": (f"Sales vs target: {pct:+.1f}% (threshold: {SALES_SHORTFALL_PCT:+.1f}%)"),
            "source": "sales",
        }
    ]


def _detect_waste_overrun(waste_items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Findings derived from the total waste quantity."""
    low, high = BOUNDS["quantity_kg"]
    total_kg = 0.0
    for index, item in enumerate(waste_items):
        if not isinstance(item, dict):
            continue
        quantity = finite_in_range(item.get("quantity_kg", 0), low, high)
        if quantity is None:
            return [_unassessable(f"waste_items[{index}].quantity_kg")]
        total_kg += quantity
    if total_kg <= WASTE_OVERRUN_KG:
        return []
    return [
        {
            "type": "waste_overrun",
            "severity": "MEDIUM",
            "description": f"Total waste {total_kg:.1f} kg exceeds threshold {WASTE_OVERRUN_KG:.1f} kg",
            "source": "waste_items",
        }
    ]


def _detect_understaffed(staff: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Finding raised when the roster is below the minimum."""
    if len(staff) >= MIN_STAFF_COUNT:
        return []
    return [
        {
            "type": "understaffed",
            "severity": "CRITICAL",
            "description": f"Shift has {len(staff)} staff member(s) — minimum is {MIN_STAFF_COUNT}",
            "source": "staff",
        }
    ]


class AnomalyDetectNode(FunctionNode):
    """Detect the operational conditions that need attention.

    Second node in DomainWorkflowGraph. escalation_required is True when any
    finding is HIGH or CRITICAL, which is what puts the escalation line in the
    report.
    """

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    def execute(self, state: Dict[str, Any], config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        shift_data: Dict[str, Any] = state.get("shift_data") or {}

        incidents: List[Dict[str, Any]] = shift_data.get("incidents") or []
        sales: Dict[str, Any] = shift_data.get("sales") or {}
        waste_items: List[Dict[str, Any]] = shift_data.get("waste_items") or []
        staff: List[Dict[str, Any]] = shift_data.get("staff") or []

        anomalies: List[Dict[str, Any]] = []
        anomalies.extend(_detect_understaffed(staff))
        anomalies.extend(_detect_from_incidents(incidents))
        anomalies.extend(_detect_from_sales(sales))
        anomalies.extend(_detect_waste_overrun(waste_items))

        escalation_required = any(str(a.get("severity", "")).upper() in _ESCALATION_SEVERITIES for a in anomalies)

        logger.info(
            "AnomalyDetectNode: found %d finding(s), escalation_required=%s",
            len(anomalies),
            escalation_required,
        )

        emit_trace_event(
            "anomaly_detection_complete",
            {
                "anomaly_count": len(anomalies),
                "escalation_required": escalation_required,
                "anomaly_types": [a.get("type") for a in anomalies],
                "store_id": shift_data.get("store_id", "<unknown>"),
                "shift_date": shift_data.get("shift_date", "<unknown>"),
            },
            state,
        )

        return {
            "anomalies": anomalies,
            "escalation_required": escalation_required,
            "status": AgentStatus.SUCCESS,
        }
