"""AgentCore Platform v1.0"""

# Node contract:
#  - Extend FunctionNode; implement execute(state, config=None) -> dict
#  - Return ONLY the fields this node changes (never full state)
#  - Return AgentStatus enum constants — never plain strings
#  - Never import from mediator/, api/, or other agents
#
# RET-C2-256 — ReportGenerateNode
# Inner DomainWorkflowGraph node 4: render the Japanese shift handover document
# (申し送り書) from the normalised shift data, the findings and the waste log.
#
# Input state keys:
#   shift_data, anomalies, escalation_required, waste_log
#
# Output state keys (partial dict returned):
#   shift_report: str
#   status: AgentStatus
#
# Two rules govern every line this node writes.
#
# 1. No caller string enters the document raw. The document's structure is carried
#    entirely by the characters in src/services/report_format.py, so a caller
#    string containing any of them — a newline above all — can write a section.
#    Driven through the real graph before this was fixed, one incident description
#    produced three copies of the regulatory food-waste block, one of them
#    reporting a total of 0.000 kg. Every caller value goes through `render_safe`.
#
# 2. Personal names are not rendered. The platform's input filter replaces values
#    it reads as personal data before any template code runs, so a roster naming
#    "Yamada Hanako" arrived here as "[MASKED]" and the shipped report named a
#    staff member `[MASKED]`, while a name written in Japanese passed through
#    unmasked — the report was simultaneously useless and disclosing, depending on
#    how the name was spelled. The roster therefore renders an inert `staff_ref`,
#    the role and the hours: identification that survives the round trip intact and
#    cannot become caller-controlled output. See docs/02_design.md.
#
# Security notes:
#   Trust: ANONYMOUS — inner node.
#   Audit: emit_trace_event on completion.

import logging
from datetime import datetime, timezone
from typing import Any, ClassVar, Dict, List, Optional

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from shared.utils.audit_logger import emit_trace_event
from src.nodes.input_parse_node import BOUNDS, MAX_DESCRIPTION_CHARS, MAX_ROLE_CHARS
from src.nodes.waste_format_node import UNREADABLE_QUANTITY_LABEL
from src.services.input_guard import finite_in_range
from src.services.report_format import (
    ESCALATION_MARK,
    INDENT,
    RULE_HEAVY,
    RULE_LIGHT,
    quote,
    render_safe,
)

logger = logging.getLogger(__name__)

# ── Labels ────────────────────────────────────────────────────────────────────

_SHIFT_LABEL_MAP = {
    "morning": "早番（開店〜昼）",
    "afternoon": "中番（昼〜夕方）",
    "night": "遅番（夕方〜閉店）",
}

_SEVERITY_LABEL_MAP = {
    "CRITICAL": "緊急",
    "HIGH": "要対応",
    "MEDIUM": "注意",
    "LOW": "経過観察",
}

_ANOMALY_TYPE_LABEL_MAP = {
    "cooler_alarm": "冷蔵/冷凍機器警報",
    "understaffed": "人員不足",
    "sales_shortfall": "売上未達",
    "incident_flag": "インシデント",
    "waste_overrun": "廃棄量超過",
    "unassessable": "判定不能（数値読み取り不可）",
}

_UNSET = "未設定"


def _shift_label(shift_type: str) -> str:
    return _SHIFT_LABEL_MAP.get(str(shift_type).lower(), render_safe(shift_type, 32) or _UNSET)


def _fmt_staff(staff: List[Dict[str, Any]]) -> str:
    """Roster lines: position, inert reference, role, hours. Never a name."""
    if not staff:
        return f"{INDENT}（スタッフ情報なし）"
    lines = []
    for position, member in enumerate(staff, start=1):
        if not isinstance(member, dict):
            continue
        # staff_ref is already held to the inert identifier shape by InputParseNode;
        # render_safe is belt-and-braces for a directly-invoked inner graph.
        ref = render_safe(member.get("staff_ref", ""), 32)
        role = render_safe(member.get("role", ""), MAX_ROLE_CHARS)
        hours = finite_in_range(member.get("hours_worked"), *BOUNDS["hours_worked"])
        line = f"{INDENT}・スタッフ{position}"
        if ref:
            line += f"[{ref}]"
        if role:
            line += f"（{role}）"
        if hours is not None:
            line += f" / {hours:g}h"
        lines.append(line)
    return "\n".join(lines) if lines else f"{INDENT}（スタッフ情報なし）"


def _fmt_sales(sales: Dict[str, Any]) -> str:
    if not sales:
        return f"{INDENT}（売上情報なし）"
    lines = []
    total_yen = finite_in_range(sales.get("total_yen"), *BOUNDS["total_yen"])
    if total_yen is not None:
        lines.append(f"{INDENT}売上合計: {total_yen:,.0f}円")
    txn = finite_in_range(sales.get("transaction_count"), *BOUNDS["transaction_count"])
    if txn is not None:
        lines.append(f"{INDENT}取引件数: {txn:,.0f}件")
    pct = finite_in_range(sales.get("vs_target_pct"), *BOUNDS["vs_target_pct"])
    if pct is not None:
        lines.append(f"{INDENT}対目標: {pct:+.1f}%")
    return "\n".join(lines) if lines else f"{INDENT}（売上情報なし）"


def _fmt_anomalies(anomalies: List[Dict[str, Any]], escalation_required: bool) -> str:
    if not anomalies:
        return f"{INDENT}異常・インシデントなし"
    lines = []
    for finding in anomalies:
        raw_type = str(finding.get("type", ""))
        label_type = _ANOMALY_TYPE_LABEL_MAP.get(raw_type, render_safe(raw_type, 40) or "不明")
        severity = _SEVERITY_LABEL_MAP.get(str(finding.get("severity", "")).upper(), "注意")
        description = render_safe(finding.get("description", ""), MAX_DESCRIPTION_CHARS)
        line = f"{INDENT}【{severity}】{label_type}"
        if description:
            line += f": {quote(description)}"
        lines.append(line)
    if escalation_required:
        lines.append(f"{INDENT}{ESCALATION_MARK} エスカレーション要 — 店長/本部への報告が必要です")
    return "\n".join(lines)


def _fmt_waste(waste_log: Dict[str, Any]) -> str:
    if not waste_log:
        return f"{INDENT}（廃棄情報なし）"
    entries = waste_log.get("entries") or []
    total_kg = finite_in_range(waste_log.get("total_kg"), *BOUNDS["quantity_kg"])
    regulation = render_safe(waste_log.get("regulation", ""), 64)
    total_text = f"{total_kg:.3f} kg" if total_kg is not None else "集計不能"
    lines = [f"{INDENT}廃棄合計: {total_text}（{regulation}）"]
    unreadable = waste_log.get("unreadable_entries") or 0
    if unreadable:
        lines.append(f"{INDENT}※ 数量を読み取れない項目が {unreadable} 件あり、合計に含まれていません")
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        item = render_safe(entry.get("item_name", ""), 120) or "不明"
        quantity = entry.get("quantity_kg")
        qty_text = (
            f"{quantity:.3f} kg"
            if isinstance(quantity, (int, float)) and not isinstance(quantity, bool)
            else UNREADABLE_QUANTITY_LABEL
        )
        category = render_safe(entry.get("category", ""), 40)
        code = render_safe(entry.get("regulatory_code", ""), 16)
        lines.append(f"{INDENT}・{item} {qty_text} [{category}] ({code})")
    return "\n".join(lines)


class ReportGenerateNode(FunctionNode):
    """Render the Japanese shift handover document (申し送り書).

    Fourth node in DomainWorkflowGraph. Assembles shift metadata, the roster,
    sales performance, the findings summary and the regulatory waste log into one
    document for the incoming shift.
    """

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    def execute(self, state: Dict[str, Any], config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        shift_data: Dict[str, Any] = state.get("shift_data") or {}
        anomalies: List[Dict[str, Any]] = state.get("anomalies") or []
        escalation_required = bool(state.get("escalation_required", False))
        waste_log: Dict[str, Any] = state.get("waste_log") or {}

        store_id = render_safe(shift_data.get("store_id") or state.get("store_id") or "", 32)
        shift_date = render_safe(shift_data.get("shift_date") or state.get("shift_date") or "", 10)
        shift_type = shift_data.get("shift_type") or state.get("shift_type") or ""
        staff: List[Dict[str, Any]] = shift_data.get("staff") or []
        sales: Dict[str, Any] = shift_data.get("sales") or {}
        incidents: List[Dict[str, Any]] = shift_data.get("incidents") or []

        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        header = (
            f"{RULE_HEAVY}\n"
            f"{INDENT}{INDENT}{INDENT}申し送り書（シフト引き継ぎ）\n"
            f"{RULE_HEAVY}\n"
            f"店舗ID  : {store_id or _UNSET}\n"
            f"日付    : {shift_date or _UNSET}\n"
            f"シフト  : {_shift_label(shift_type)}\n"
            f"記録日時: {generated_at}\n"
        )

        staff_section = f"{RULE_LIGHT}\n【スタッフ情報】\n" + _fmt_staff(staff)
        sales_section = f"\n{RULE_LIGHT}\n【売上情報】\n" + _fmt_sales(sales)
        anomaly_section = f"\n{RULE_LIGHT}\n【異常・インシデント】\n" + _fmt_anomalies(anomalies, escalation_required)
        waste_section = f"\n{RULE_LIGHT}\n【食品廃棄ログ（食品ロス削減推進法）】\n" + _fmt_waste(waste_log)

        footer = (
            f"\n{RULE_LIGHT}\n"
            "【引き継ぎ事項】\n"
            f"{INDENT}異常件数: {len(anomalies)}件 / インシデント: {len(incidents)}件\n"
            f"{INDENT}次シフト担当者への特記事項は上記を参照してください。\n"
            "※ スタッフは個人名ではなく勤務照合ID（staff_ref）で記載しています。\n"
            f"{RULE_HEAVY}"
        )

        shift_report = "\n".join([header, staff_section, sales_section, anomaly_section, waste_section, footer])

        logger.info(
            "ReportGenerateNode: rendered handover for store=%s date=%s shift=%s len=%d",
            store_id,
            shift_date,
            shift_type,
            len(shift_report),
        )

        emit_trace_event(
            "shift_report_generated",
            {
                "store_id": store_id,
                "shift_date": shift_date,
                "shift_type": str(shift_type),
                "report_length": len(shift_report),
                "anomaly_count": len(anomalies),
                "escalation_required": escalation_required,
            },
            state,
        )

        return {
            "shift_report": shift_report,
            "status": AgentStatus.SUCCESS,
        }
