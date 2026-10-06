"""AgentCore Platform v1.0"""

# RET-C2-256 — the structural vocabulary of the handover document, and the one
# function that makes caller text safe to place inside it.
#
# The renderer and the sanitiser must agree on this vocabulary exactly. The
# handover report is a structured document: a reader — and the next shift — tells
# a section heading from a line of prose by these characters alone. If a caller
# can emit any of them, a caller can write a section.
#
# That is not hypothetical. Driven through the real graph, an incident
# description carrying newlines produced three copies of the regulatory
# food-waste section — one of them announcing a total of 0.000 kg — and three
# copies of the escalation line, all inside a success envelope. The food-waste
# block is a regulatory record, so it is the worst line in the document for a
# caller to be able to write.
#
# Two copies of these constants would drift, and a drifted sanitiser passes
# everything, so both sides import them from here.

import re
import unicodedata
from typing import Any, Dict

# ── Document vocabulary ───────────────────────────────────────────────────────
# Every character below carries structural meaning in the rendered report.
RULE_CHAR_HEAVY = "═"  # heavy rule, header and footer
RULE_CHAR_LIGHT = "─"  # light rule, between sections
INDENT = "　"  # ideographic space — the report's left margin
BULLET = "・"
ESCALATION_MARK = "★"
HEADING_OPEN = "【"
HEADING_CLOSE = "】"

RULE_HEAVY = RULE_CHAR_HEAVY * 39
RULE_LIGHT = RULE_CHAR_LIGHT * 39

# The redaction sentinel the platform's input filter substitutes for values it
# classifies as personal data. It arrives as an ordinary string, so anything that
# renders or certifies caller values has to recognise it rather than treat it as
# content — see `is_redacted`.
REDACTION_SENTINEL = "[MASKED]"
REDACTED_LABEL = "（伏字 / redacted）"

# Characters a caller string may never carry into the document. Newlines lead the
# list: a newline alone is enough to begin a line that looks like one of ours.
_STRUCTURAL_CHARS = frozenset(
    {
        "\n",
        "\r",
        "\t",
        "\v",
        "\f",
        RULE_CHAR_HEAVY,
        RULE_CHAR_LIGHT,
        INDENT,
        BULLET,
        ESCALATION_MARK,
        HEADING_OPEN,
        HEADING_CLOSE,
    }
)

_WHITESPACE_RUN = re.compile(r"\s+")

# Default ceiling for a rendered caller string. Fields with tighter needs pass
# their own; nothing renders unbounded, because 2,000 waste entries of 200
# characters each produced a 474 KB report.
DEFAULT_RENDER_LIMIT = 200

TRUNCATION_MARK = "…"


def is_redacted(value: object) -> bool:
    """True when the platform's input filter replaced this value.

    A redaction sentinel is evidence that a value was withheld, never evidence of
    what the value was. Reporting it as if it were the caller's data is how a
    template ends up presenting `[MASKED]` as a person's name.
    """
    return isinstance(value, str) and REDACTION_SENTINEL in value


def render_safe(value: object, limit: int = DEFAULT_RENDER_LIMIT) -> str:
    """Reduce caller text to something that cannot forge document structure.

    Control characters and every structural character become a single space, runs
    of whitespace collapse to one, and the result is bounded. Unicode
    format and control CATEGORIES are removed wholesale rather than enumerated, so
    a bidirectional override or a zero-width joiner cannot be used to make one
    line read as another.

    The value is neutralised, not rejected: an item name is legitimate free text
    and the report needs it. Rejection belongs to the screens in
    `src/services/input_guard.py`, which run first and refuse the request outright
    when the text is hostile rather than merely awkward.
    """
    if not isinstance(value, str):
        return ""
    if is_redacted(value):
        return REDACTED_LABEL

    out_chars = []
    for char in value:
        if char in _STRUCTURAL_CHARS:
            out_chars.append(" ")
            continue
        # Cc control, Cf format (RLO/LRO/ZWJ...), Cs surrogate, Zl/Zp separators.
        if unicodedata.category(char) in {"Cc", "Cf", "Cs", "Zl", "Zp"}:
            out_chars.append(" ")
            continue
        out_chars.append(char)

    collapsed = _WHITESPACE_RUN.sub(" ", "".join(out_chars)).strip()
    if not collapsed:
        return ""
    if limit > 0 and len(collapsed) > limit:
        return collapsed[: max(limit - 1, 1)] + TRUNCATION_MARK
    return collapsed


def quote(value: str) -> str:
    """Wrap rendered caller text in corner brackets.

    Used where caller text sits on the same line as our own prose. The brackets
    are not the security control — `render_safe` is — they mark for a human reader
    where the document stops speaking and the caller's words start.
    """
    return f"「{value}」" if value else ""


# ── The error envelope ────────────────────────────────────────────────────────
# `AgentBaseGraph.get_output` returns `state["formatted_output"] or
# state["result"]`, so the error envelope is a caller-visible channel and the
# `or` is a fallback that a FALSY formatted_output re-opens onto the un-gated
# inner answer. Two facts follow, and both are enforced at every refusal site:
#
#   1. the refusal notice must be TRUTHY, or the fallback fires;
#   2. `result` must be cleared, or the fallback has something to serve.
#
# The notice itself is assembled from CLOSED-SET labels only — a reason code and
# an inert field location. Nothing node-authored is re-emitted: `error_log`
# carries node text and, wherever a node interpolates a caught exception, upstream
# message bodies, so truncating or redacting it is not a closed error contract.
# `error_log` is not projected by `get_output` today, which is a reason to keep it
# clean rather than a reason to relax it.

REFUSAL_TITLE = "この申し送り要求は処理できません / This handover request cannot be processed."

# State fields that can carry generated document text. Cleared together at every
# refusal so the envelope has nothing to fall back onto.
OUTPUT_BEARING_FIELDS = (
    "result",
    "validated_output",
    "shift_report",
    "bilingual_summary",
)


def refusal_notice(reason: str, location: str = "") -> str:
    """A truthy, closed-set caller notice for a refused request.

    ``reason`` is one of the labels in `src/services/input_guard.py`; ``location``
    is an inert field path or empty. Neither the rejected value nor any generated
    document text appears here.
    """
    where = f" (field: {location})" if location else ""
    return f"{REFUSAL_TITLE}\nreason: {reason}{where}"


def contained_refusal(reason: str, location: str = "") -> Dict[str, Any]:
    """State delta that refuses a request and leaves nothing for the fallback.

    Returns the notice under ``formatted_output`` AND empties every
    output-bearing field. Both halves are needed and each is separately
    falsifiable: drop the notice and the envelope carries no reason, drop the
    clearing and `result` serves the un-gated document.

    Partial deltas are merged, so the fields are set to an empty string rather
    than omitted — an omitted key leaves the previous value in place.
    """
    delta = {field: "" for field in OUTPUT_BEARING_FIELDS}
    delta["formatted_output"] = refusal_notice(reason, location)
    return delta
