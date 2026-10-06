"""AgentCore Platform v1.0"""

# ADR-005: State must be a flat TypedDict — never Pydantic BaseModel.
# LangGraph checkpoints use msgpack serialization; Pydantic objects
# cause silent corruption.  Extend AgentState with agent-specific
# fields only.  Do NOT add credentials, secrets, or Pydantic models.

from typing import Any, Dict, List, Optional

from framework.schemas.agent_state import AgentState


class State(AgentState):
    """Agent state for RET-C2-256 Retail Franchise Shift Handover Report.

    All shared fields (user_input, status, session_id, node_history,
    error_log, hitl_*, validated_input, result, formatted_output, etc.)
    are inherited from AgentState.

    Domain-specific fields below represent the pipeline's intermediate
    and final results produced by the inner DomainWorkflowGraph nodes.
    All fields are Optional — never absent-key on partial state updates.
    """

    # ── Pre-process output ─────────────────────────────────────────────
    # store_id / shift_date / shift_type extracted by PreProcessNode from
    # the validated_input metadata; also set by InputParseNode inside the
    # inner graph if not already present.
    store_id: Optional[str]
    shift_date: Optional[str]
    shift_type: Optional[str]

    # ── InputParseNode output ──────────────────────────────────────────
    # Structured shift payload parsed from the JSON user_input.
    # Keys: staff (list), sales (dict), incidents (list), waste_items (list).
    shift_data: Optional[Dict[str, Any]]

    # ── AnomalyDetectNode output ───────────────────────────────────────
    # List of detected anomaly dicts: {type, severity, description, node}.
    anomalies: Optional[List[Dict[str, Any]]]
    # True when at least one anomaly requires management escalation.
    escalation_required: Optional[bool]

    # ── WasteFormatNode output ─────────────────────────────────────────
    # Shokuhin-Loss Reduction Promotion Act FY2026 formatted waste log.
    # Keys: store_id, date, entries (list of waste entry dicts), total_kg.
    waste_log: Optional[Dict[str, Any]]

    # ── ReportGenerateNode output ──────────────────────────────────────
    # Full Japanese shift handover report (申し送り書 / Moshiokuri-sho) text.
    shift_report: Optional[str]

    # ── MultilingualAdaptNode output ───────────────────────────────────
    # Compact bilingual summary: Japanese block + Vietnamese/English block.
    bilingual_summary: Optional[str]

    # ── ResponseValidateNode output ────────────────────────────────────
    # Final sanitized output — passes the S-3 credential/PII scan.
    validated_output: Optional[str]
