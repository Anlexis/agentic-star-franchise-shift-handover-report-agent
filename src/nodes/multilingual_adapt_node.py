"""AgentCore Platform v1.0"""

# Node contract:
#  - Extend FunctionNode; implement execute(state, config=None) -> dict
#  - Return ONLY the fields this node changes (never full state)
#  - Return AgentStatus enum constants — never plain strings
#  - Never import from mediator/, api/, or other agents
#
# RET-C2-256 — MultilingualAdaptNode
# Inner DomainWorkflowGraph node 5: a short handover summary in Japanese and in
# Vietnamese/English, for stores whose incoming shift does not read Japanese
# fluently.
#
# Input state keys:
#   shift_data, anomalies, escalation_required, waste_log
#
# Output state keys (partial dict returned):
#   bilingual_summary: str — a Japanese block followed by a Vietnamese/English block
#   status: AgentStatus
#
# Two corrections worth stating, because both produced wrong documents:
#
#   - The findings list is rendered in the order it was detected. It used to be
#     built from a SET comprehension, so the order came from string hashing:
#     across six processes the same three findings came out in three different
#     orders. A handover document whose text changes between runs for identical
#     input cannot be reconciled against the shift it describes.
#
#   - Every number is read through the finite + bounded parser. A bare `float()`
#     on the caller's `vs_target_pct` raised on any non-numeric value, and the
#     framework returned the whole run as an error with an empty error_log — an
#     ordinary typo in one optional field killed the request with no diagnosis.
#
# The summary is generated from the structured state, not translated: no model is
# invoked anywhere in this template, which is what `generation_mode: deterministic`
# in the manifest declares.
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
from src.services.report_format import quote, render_safe

logger = logging.getLogger(__name__)

# ── Labels ────────────────────────────────────────────────────────────────────

_SHIFT_LABELS_JA = {"morning": "早番", "afternoon": "中番", "night": "遅番"}
_SHIFT_LABELS_EN = {"morning": "Morning shift", "afternoon": "Afternoon shift", "night": "Night shift"}
_SHIFT_LABELS_VI = {"morning": "Ca sáng", "afternoon": "Ca chiều", "night": "Ca tối"}

_ANOMALY_LABELS_EN = {
    "cooler_alarm": "cooler/freezer alarm",
    "understaffed": "understaffed",
    "sales_shortfall": "sales shortfall",
    "incident_flag": "incident",
    "waste_overrun": "waste overrun",
    "unassessable": "value could not be assessed",
}
_ANOMALY_LABELS_VI = {
    "cooler_alarm": "báo động tủ lạnh/tủ đông",
    "understaffed": "thiếu nhân viên",
    "sales_shortfall": "doanh thu không đạt",
    "incident_flag": "sự cố",
    "waste_overrun": "thừa lãng phí thực phẩm",
    "unassessable": "không thể đánh giá giá trị",
}

# How many findings the short summary names before it stops. The full list is in
# the Japanese document; this block exists to be readable at a glance.
SUMMARY_FINDING_LIMIT = 3


def _shift_labels(shift_type: Any) -> Dict[str, str]:
    key = str(shift_type).lower()
    fallback = render_safe(shift_type, 32)
    return {
        "ja": _SHIFT_LABELS_JA.get(key, fallback),
        "en": _SHIFT_LABELS_EN.get(key, fallback),
        "vi": _SHIFT_LABELS_VI.get(key, fallback),
    }


def _total_kg(waste_log: Dict[str, Any]) -> Optional[float]:
    if not waste_log:
        return 0.0
    return finite_in_range(waste_log.get("total_kg", 0.0), *BOUNDS["quantity_kg"])


def _build_ja_summary(
    shift_data: Dict[str, Any],
    anomalies: List[Dict[str, Any]],
    escalation_required: bool,
    waste_log: Dict[str, Any],
) -> str:
    store_id = render_safe(shift_data.get("store_id", ""), 32)
    shift_date = render_safe(shift_data.get("shift_date", ""), 10)
    staff = shift_data.get("staff") or []
    sales = shift_data.get("sales") or {}

    total_yen = finite_in_range(sales.get("total_yen"), *BOUNDS["total_yen"])
    pct = finite_in_range(sales.get("vs_target_pct"), *BOUNDS["vs_target_pct"])
    total_kg = _total_kg(waste_log)

    sales_text = f"{total_yen:,.0f}円" if total_yen is not None else "不明"
    pct_text = f"（対目標: {pct:+.1f}%）" if pct is not None else ""
    waste_text = f"{total_kg:.3f} kg" if total_kg is not None else "集計不能"

    lines = [
        "【日本語要約】",
        f"店舗: {store_id}　日付: {shift_date}　シフト: {_shift_labels(shift_data.get('shift_type'))['ja']}",
        f"スタッフ: {len(staff)}名　売上: {sales_text}{pct_text}",
        f"廃棄合計: {waste_text}",
    ]
    if anomalies:
        # Detection order, preserved. A set here made the same input render in a
        # different order from one process to the next.
        named = "、".join(
            quote(render_safe(a.get("description", "") or a.get("type", ""), 60))
            for a in anomalies[:SUMMARY_FINDING_LIMIT]
        )
        lines.append(f"異常: {len(anomalies)}件 — {named}")
    else:
        lines.append("異常: なし")
    if escalation_required:
        lines.append("⚠ エスカレーション必要: 店長への報告を行ってください")
    return "\n".join(lines)


def _build_vi_en_summary(
    shift_data: Dict[str, Any],
    anomalies: List[Dict[str, Any]],
    escalation_required: bool,
    waste_log: Dict[str, Any],
) -> str:
    store_id = render_safe(shift_data.get("store_id", ""), 32)
    shift_date = render_safe(shift_data.get("shift_date", ""), 10)
    staff = shift_data.get("staff") or []
    labels = _shift_labels(shift_data.get("shift_type"))
    total_kg = _total_kg(waste_log)
    waste_text = f"{total_kg:.3f} kg" if total_kg is not None else "n/a"

    lines = [
        "【Tóm tắt tiếng Việt / English Summary】",
        f"Cửa hàng / Store: {store_id}",
        f"Ngày / Date: {shift_date}",
        f"Ca làm việc / Shift: {labels['vi']} / {labels['en']}",
        f"Số nhân viên / Staff count: {len(staff)}",
        f"Tổng thực phẩm lãng phí / Food waste total: {waste_text}",
    ]
    if anomalies:
        # Category labels only — closed sets, so this block carries no caller text.
        selected = anomalies[:SUMMARY_FINDING_LIMIT]
        vi = ", ".join(_ANOMALY_LABELS_VI.get(str(a.get("type", "")), "khác") for a in selected)
        en = ", ".join(_ANOMALY_LABELS_EN.get(str(a.get("type", "")), "other") for a in selected)
        lines.append(f"Vấn đề / Issues: {vi} / {en}")
    else:
        lines.append("Vấn đề / Issues: Không có / None")
    if escalation_required:
        lines.append("⚠ Cần báo cáo quản lý / Manager notification required")
    return "\n".join(lines)


class MultilingualAdaptNode(FunctionNode):
    """Build the bilingual handover summary (Japanese + Vietnamese/English).

    Fifth node in DomainWorkflowGraph. Two language blocks: Japanese for the store
    manager, Vietnamese and English for staff who do not read Japanese fluently.
    """

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    def execute(self, state: Dict[str, Any], config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        shift_data: Dict[str, Any] = state.get("shift_data") or {}
        anomalies: List[Dict[str, Any]] = state.get("anomalies") or []
        escalation_required = bool(state.get("escalation_required", False))
        waste_log: Dict[str, Any] = state.get("waste_log") or {}

        ja_block = _build_ja_summary(shift_data, anomalies, escalation_required, waste_log)
        vi_en_block = _build_vi_en_summary(shift_data, anomalies, escalation_required, waste_log)
        bilingual_summary = ja_block + "\n\n" + vi_en_block

        logger.info(
            "MultilingualAdaptNode: summary len=%d for store=%s",
            len(bilingual_summary),
            shift_data.get("store_id", ""),
        )

        emit_trace_event(
            "multilingual_summary_created",
            {
                "store_id": shift_data.get("store_id", ""),
                "shift_date": shift_data.get("shift_date", ""),
                "summary_length": len(bilingual_summary),
                "languages": ["ja", "vi", "en"],
                "anomaly_count": len(anomalies),
            },
            state,
        )

        return {
            "bilingual_summary": bilingual_summary,
            "status": AgentStatus.SUCCESS,
        }
