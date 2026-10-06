"""AgentCore Platform v1.0"""

# RET-C2-256 — caller-input screening, shared by the HTTP entry point and the
# nodes that own the caller contract.
#
# Three rules drive this module.
#
# 1. The template owns its guarantees. The framework screens the request text,
#    but a deployment can put this agent behind a different front door, so the
#    node that accepts caller data screens it too and refuses in its own right.
#    Refusals are asserted behaviourally — error status, nothing carried forward —
#    never by matching a message.
#
# 2. Screen the class, not the example. Chat-template control markers are a
#    family: `<|...|>`, `[INST]`, `<<SYS>>`, `<s>`, `<system>`. The framework
#    scores `<|im_start|>` and `[INST]` as high confidence but returns nothing at
#    all for `<<SYS>>`, so a directive wrapped in that marker reaches the report
#    and is rendered back to the reader.
#
# 3. Take the UNION of every credential detector, never one instead of another.
#    Measured against the installed framework on this repo's own values:
#
#      shape                    template patterns   framework detector
#      password=… / api_key:…   refuse              pass
#      Authorization: …         refuse              pass
#      user:pass@host           refuse              pass
#      AKIA… / sk_live_… / sk-… pass                refuse
#      JWT eyJ…                 pass                refuse
#      glpat-…                  pass                pass
#
#    Each column catches four shapes the other misses, so replacing either with
#    the other would NARROW the gate while looking like a tightening. The third
#    row is worse: a `glpat-`-shaped token in an incident description was driven
#    through the real graph and came back verbatim to the caller inside a SUCCESS
#    envelope, because neither detector carries that shape. `_VCS_TOKEN_RE` exists
#    for that measured gap.
#
# Refusal reasons come from a CLOSED SET of labels. A reason names a location and
# a category, never the matched text: quoting the offending value back would put
# it into the error path this module exists to keep clean.

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from framework.security.credential_detector import detect_credentials_in_value
from framework.security.injection_detector import detect_injection

# ── Closed set of refusal reasons ─────────────────────────────────────────────
# Callers surface these verbatim; nothing else crosses the boundary.
REASON_CONTROL_TOKEN = "control_token"
REASON_INJECTION = "injection_directive"
REASON_CREDENTIAL = "credential_shape"
REASON_PII = "personal_data_shape"
REASON_INVALID_IDENTIFIER = "invalid_identifier"
REASON_NOT_FINITE = "not_a_finite_number"
REASON_OUT_OF_RANGE = "out_of_range"
REASON_TOO_LONG = "value_too_long"
REASON_TOO_MANY = "too_many_entries"
REASON_WRONG_TYPE = "wrong_type"
REASON_MISSING = "missing_required_field"
REASON_MALFORMED = "malformed_payload"
REASON_UNSUPPORTED_FIELD = "unsupported_field"
# Used when a refusal is known to have happened upstream but its label cannot be
# recovered from the closed set — see `project_refusal`.
REASON_UPSTREAM = "upstream_refusal"

KNOWN_REASONS: Tuple[str, ...] = (
    REASON_CONTROL_TOKEN,
    REASON_INJECTION,
    REASON_CREDENTIAL,
    REASON_PII,
    REASON_INVALID_IDENTIFIER,
    REASON_NOT_FINITE,
    REASON_OUT_OF_RANGE,
    REASON_TOO_LONG,
    REASON_TOO_MANY,
    REASON_WRONG_TYPE,
    REASON_MISSING,
    REASON_MALFORMED,
    REASON_UNSUPPORTED_FIELD,
    REASON_UPSTREAM,
)

# A refusal location is built only from literal field names, inert caller field
# labels and numeric indices, so it is safe to show. This pattern is the proof of
# that rather than a restatement of it: a location that does not match is dropped,
# so a future caller-derived location cannot ride out on this channel.
_LOCATION_RE = re.compile(r"^[A-Za-z0-9_.\[\]# -]{1,64}$")
_REFUSAL_ENTRY_RE = re.compile(r"\b(?P<reason>[a-z_]{4,32})\b(?:\s*\((?P<location>[^()]{0,64})\))?")

# ── Chat-template control markers ─────────────────────────────────────────────
# `<|...|>` and `[INST]`/`[SYS]` overlap with the framework's own high-confidence
# set deliberately — this template must not be the narrower screen. `<<SYS>>`,
# `<</SYS>>`, `<s>` and `</s>` are the members the framework does not score, and
# are the reason this pattern exists at all.
_CONTROL_TOKEN_RE = re.compile(
    r"<\|[^|>]{0,64}\|>"  # <|im_start|>, <|endoftext|>, ...
    r"|<{2}\s*/?\s*SYS\s*>{2}"  # <<SYS>>, <</SYS>>
    r"|\[/?\s*(?:INST|SYS)\s*\]"  # [INST], [/INST], [SYS]
    r"|</?\s*s\s*>"  # <s>, </s>
    r"|</?\s*(?:system|user|assistant)\s*>",  # <system>, </assistant>, ...
    re.IGNORECASE,
)

# Inline markup, removed for the second pass so a directive split across tags is
# re-assembled before it is screened ("ig<b>nore</b> all previous instructions").
_MARKUP_RE = re.compile(r"<[^<>]{0,200}>")

# ── Directive, SQL and script markers ─────────────────────────────────────────
# These are the screens this template shipped, kept because the framework's
# detector is NARROWER on every one of them. Measured against the installed
# detector: of the directive/SQL/script cases this repo already refused, it scores
# only "ignore all previous instructions" and "UNION ALL SELECT" as high
# confidence — 11 of 13 would have been let through by delegating to it. Wider is
# safe; narrower is a bypass, and a replacement that looks like a tightening is
# the easiest version of that mistake to make.
#
# Two of them are ANCHORED here rather than carried over verbatim, because the
# shipped forms fired on ordinary retail sentences in a retail template:
# "Insert into stock room shelf 3 the returned bento" and "Update the set menu
# price tag" were both refused by a bare verb-pair match. SQL needs statement
# context — a target followed by an argument list, VALUES, an assignment, WHERE or
# a terminator — and requiring it keeps the screen closed against real SQL while
# opening it to the sentences a shift actually writes.
_DIRECTIVE_RE: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    # Prompt-directive shapes.
    (
        "ignore_instructions",
        re.compile(r"(?i)ignore\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above)\s+(?:instructions|prompts?)"),
    ),
    ("disregard", re.compile(r"(?i)disregard\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above)")),
    ("forget", re.compile(r"(?i)forget\s+(?:everything|all\s+(?:previous|prior)|your\s+instructions)")),
    ("system_prompt", re.compile(r"(?i)\bsystem\s+prompt\b")),
    # Role override, anchored on the assumption of a different identity. The bare
    # "you are now" form this replaces fires on an ordinary handover instruction —
    # "you are now responsible for the register" — which is what this document is
    # for.
    (
        "role_override",
        re.compile(
            r"(?i)you\s+are\s+(?:now\s+)?(?:a|an|the)?\s*"
            r"(?:unrestricted|unfiltered|uncensored|jailbroken|developer\s+mode|dan\b|"
            r"admin(?:istrator)?|root|sudo|system|assistant|ai\s+model|language\s+model|"
            r"no\s+longer\s+bound|not\s+bound\s+by)"
        ),
    ),
    (
        "reveal_prompt",
        re.compile(
            r"(?i)(?:reveal|show|print|leak|repeat)\s+(?:me\s+)?(?:your\s+|the\s+)?(?:system\s+)?(?:prompt|instructions)"
        ),
    ),
    # SQL, with statement context required.
    ("sql_union", re.compile(r"(?i)\bunion\s+(?:all\s+)?select\b")),
    ("sql_insert", re.compile(r"(?i)\binsert\s+into\s+[\w.\"`\[\]]+\s*(?:\(|values\b|select\b)")),
    ("sql_update", re.compile(r"(?i)\bupdate\s+[\w.\"`\[\]]+\s+set\s+[\w.\"`\[\]]+\s*=")),
    ("sql_delete", re.compile(r"(?i)\bdelete\s+from\s+[\w.\"`\[\]]+\s*(?:where\b|;|$)")),
    ("sql_drop", re.compile(r"(?i)\b(?:drop|truncate)\s+table\s+(?:if\s+exists\s+)?[\w.\"`\[\]]+\s*(?:;|$)")),
    ("sql_tautology", re.compile(r"(?i)'\s*or\s+'?\d+'?\s*=\s*'?\d+")),
    ("sql_comment", re.compile(r"(?:'|\")\s*;\s*--")),
    # Script and markup execution.
    ("script_tag", re.compile(r"(?i)<\s*/?\s*script\b")),
    ("script_js_uri", re.compile(r"(?i)javascript\s*:")),
    ("script_handler", re.compile(r"(?i)\bon(?:error|load|click|mouseover|focus)\s*=")),
    ("script_iframe", re.compile(r"(?i)<\s*iframe\b")),
    ("script_eval", re.compile(r"(?i)\beval\s*\(")),
    ("script_cookie", re.compile(r"(?i)document\s*\.\s*cookie")),
)

# ── Credential shapes ─────────────────────────────────────────────────────────
# Kept because the framework's detector describes credential FORMATS and matches
# none of these assignment shapes. Dropping any of them in favour of "delegating
# to the framework" would widen what this agent publishes.
_LOCAL_CREDENTIAL_RE: Tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)(?:password|passwd|secret|api[_-]?key|token)\s*[:=]\s*\S+"),
    re.compile(r"(?i)authorization\s*:\s*\S+"),
    re.compile(r"[A-Za-z0-9._%+-]+:[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
)

# Forge/platform access tokens that NEITHER the framework detector nor the
# assignment patterns above recognise. Measured, not assumed: a `glpat-` token
# placed in an incident description reached the caller verbatim.
_VCS_TOKEN_RE = re.compile(
    r"\bglpat-[A-Za-z0-9_\-]{16,}"  # GitLab personal access token
    r"|\bgl(?:dt|rt|soat|ptt)-[A-Za-z0-9_\-]{16,}"  # other GitLab token families
    r"|\bgh[pousr]_[A-Za-z0-9]{16,}"  # GitHub classic tokens
    r"|\bgithub_pat_[A-Za-z0-9_]{20,}"  # GitHub fine-grained tokens
    r"|\bxox[abprs]-[A-Za-z0-9\-]{10,}"  # Slack tokens
    r"|\bnpm_[A-Za-z0-9]{30,}"  # npm automation tokens
)

# ── Rendered-value shapes ─────────────────────────────────────────────────────
# Short caller strings that reach the document as identifiers are locked to an
# inert alphabet. Store codes are upper-case with hyphens ("LAWSON-7-001") and
# staff references use the same alphabet, so the class is broader than the
# lower-case convention some peers use — it is written from this repo's own
# render alphabet rather than assumed.
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9_\-]{1,32}$")

# Field names are caller data too — a name is echoed only when it is itself inert.
_FIELD_NAME_RE = re.compile(r"^[a-z0-9_]{1,32}$")

# ── Personal-data shapes ──────────────────────────────────────────────────────
# The framework's own filter masks what it recognises before this code runs, and
# its word-boundary handling does not fire on unspaced Japanese text, so these run
# as the template's own screen rather than as a duplicate of the platform's.
# Anchored and structured so ordinary shift data — dates, store codes, yen totals,
# kilogram quantities — cannot match.
_PII_RE: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    ("email", re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")),
    ("phone_jp", re.compile(r"(?<!\d)0\d{1,4}-\d{1,4}-\d{4}(?!\d)")),
    ("phone_intl", re.compile(r"(?<![\d+])\+\d{1,3}[-\s]?\d{2,4}[-\s]?\d{3,4}[-\s]?\d{3,4}(?!\d)")),
    ("phone_generic", re.compile(r"(?<!\d)\d{3}-\d{3,4}-\d{4}(?!\d)")),
    ("phone_bare", re.compile(r"(?<!\d)0\d{9,10}(?!\d)")),
    ("card_grouped", re.compile(r"(?<!\d)(?:\d{4}[-\s]){3}\d{4}(?!\d)")),
    ("card_bare", re.compile(r"(?<!\d)\d{15,16}(?!\d)")),
    # 個人番号 (My Number) written without separators, which is how Japanese text
    # normally writes it. A word-boundary pattern computed over \w never fires
    # here, because Kana and Kanji are word characters.
    ("my_number", re.compile(r"(?<!\d)\d{4}[-\s]?\d{4}[-\s]?\d{4}(?!\d)")),
)


def project_refusal(error_log: Any) -> Tuple[str, str]:
    """Recover the closed-set ``(reason, location)`` from an upstream error log.

    The inner graph's refusal reaches the outer graph only as a raised
    SubgraphError carrying the inner error_log — the framework does not hand the
    inner result to `merge_output` on an error status — so the outer boundary has
    to recover the caller's reason from that text.

    Recovering is not echoing. A label is emitted only if it is a MEMBER of
    KNOWN_REASONS, and a location only if it matches the inert shape above.
    Anything else degrades to `upstream_refusal` with no location, so no
    node-authored text and no caller value can reach the envelope through here.
    """
    entries = error_log if isinstance(error_log, (list, tuple)) else [error_log]
    for entry in entries:
        if not isinstance(entry, str):
            continue
        for match in _REFUSAL_ENTRY_RE.finditer(entry):
            reason = match.group("reason")
            if reason not in KNOWN_REASONS:
                continue
            location = (match.group("location") or "").strip()
            if not _LOCATION_RE.match(location):
                location = ""
            return reason, location
    return REASON_UPSTREAM, ""


def screen_text(value: Any) -> Optional[str]:
    """Return a closed-set refusal reason for a caller string, or None.

    Screened raw AND markup-stripped; the union of both passes decides. The raw
    pass catches a control token before stripping could remove it — a sanitiser
    that silently deletes `<|im_start|>` converts a detectable token attack into
    undetectable plain text — and the stripped pass catches a directive spliced
    across inline tags.
    """
    if not isinstance(value, str) or not value:
        return None
    candidates = [value]
    # Removed, not replaced with a space: the point of the second pass is to
    # re-assemble a word a tag was inserted into.
    stripped = _MARKUP_RE.sub("", value)
    if stripped != value:
        candidates.append(stripped)
    for candidate in candidates:
        if _CONTROL_TOKEN_RE.search(candidate):
            return REASON_CONTROL_TOKEN
        # The union, in both directions: this template's own directive/SQL/script
        # patterns, AND the framework's detector. Neither is a superset of the
        # other, so dropping either narrows the screen.
        if any(pattern.search(candidate) for _label, pattern in _DIRECTIVE_RE):
            return REASON_INJECTION
        if any(f.get("confidence") == "high" for f in detect_injection(candidate)):
            return REASON_INJECTION
        if screen_credentials(candidate):
            return REASON_CREDENTIAL
        if screen_pii(candidate):
            return REASON_PII
    return None


def screen_credentials(value: Any) -> bool:
    """True when ANY detector recognises a credential shape in this value.

    The union of three sources — see the table at the top of this module. The
    framework's own detector is the floor, so a value it would raise on deeper in
    the pipeline is refused here instead, where the reason is actionable and this
    template's clearing is not discarded along with the node's delta.
    """
    if detect_credentials_in_value(value):
        return True
    if not isinstance(value, str):
        return False
    if _VCS_TOKEN_RE.search(value):
        return True
    return any(pattern.search(value) for pattern in _LOCAL_CREDENTIAL_RE)


def screen_pii(value: Any) -> Optional[str]:
    """Return the category of the first personal-data shape found, else None."""
    if not isinstance(value, str):
        return None
    for label, pattern in _PII_RE:
        if pattern.search(value):
            return label
    return None


def safe_field_label(name: Any, index: int) -> str:
    """A field name that is safe to put in an error message.

    The name is caller data: echo it only when it is an inert identifier that
    trips no credential pattern of its own. Otherwise report it positionally.
    """
    if isinstance(name, str) and _FIELD_NAME_RE.match(name) and not screen_credentials(name):
        return name
    return f"field #{index}"


def screen_payload(payload: Any, path: str = "") -> Optional[Tuple[str, str]]:
    """Depth-first screen of a parsed payload, KEYS included.

    Returns ``(reason, location)`` for the first refusal, or None. A JSON `\\u`
    escape is decoded before this code sees it, so scanning after the parse is
    what makes escaping useless; and a hostile field NAME is caller data exactly
    like a value. ``location`` is a dotted path built only from inert names, so it
    can be shown to the caller.
    """
    if isinstance(payload, dict):
        for index, (key, value) in enumerate(payload.items(), start=1):
            label = safe_field_label(key, index)
            here = f"{path}.{label}" if path else label
            if isinstance(key, str):
                reason = screen_text(key)
                if reason:
                    return reason, here
            found = screen_payload(value, here)
            if found:
                return found
        return None
    if isinstance(payload, (list, tuple)):
        for index, item in enumerate(payload):
            found = screen_payload(item, f"{path}[{index}]")
            if found:
                return found
        return None
    if isinstance(payload, str):
        reason = screen_text(payload)
        if reason:
            return reason, path or "value"
    return None


def screen_request(raw_input: Any) -> Optional[Tuple[str, str]]:
    """Screen a whole request body: the raw text, then the parsed structure.

    Returns ``(reason, location)`` or None. This is the composition the entry node
    and the HTTP adapter both use, so the two cannot drift into screening
    different things.

    The raw pass comes first on purpose: a control marker has to be caught before
    any markup handling could remove it and forward the directive residue as
    ordinary text. The parsed pass then walks keys and values depth-first, which is
    what makes a `\\u` escape useless — the parser has already decoded it.
    """
    if not isinstance(raw_input, str):
        return REASON_WRONG_TYPE, "input"
    reason = screen_text(raw_input)
    if reason:
        return reason, "input"
    try:
        parsed = json.loads(raw_input)
    except (json.JSONDecodeError, TypeError, ValueError):
        # Not JSON. The structural verdict belongs to the parsing node, which
        # refuses with its own closed-set reason.
        return None
    return screen_payload(parsed)


def normalise_identifier(raw: Any) -> Optional[str]:
    """Validate a caller identifier against the inert shape.

    Returns the value unchanged when it fits, else None. Callers must treat None
    as a refusal — never as "use the raw value".
    """
    if not isinstance(raw, str):
        return None
    candidate = raw.strip()
    if not _IDENTIFIER_RE.match(candidate):
        return None
    return candidate


def finite_in_range(value: Any, low: float, high: float) -> Optional[float]:
    """Return ``value`` as a finite float inside ``[low, high]``, else None.

    Rejects bools (``isinstance(True, int)`` is True in Python), non-numeric
    strings, NaN and ±Infinity, and anything outside the declared bounds.

    Non-finite values are the reason this exists rather than a bare ``float()``.
    Python's ``json`` parses bare ``NaN`` and ``Infinity`` out of a request body,
    ``float()`` accepts both, and every comparison against NaN is False — so a NaN
    waste quantity sailed through the overrun check that the anomaly detector
    exists to make, reported ``nan kg`` in a regulatory log, and returned success.
    Fails CLOSED: the caller gets a refusal naming the field.
    """
    if isinstance(value, bool) or value is None:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    # NaN fails both comparisons; ±Infinity fails one. Neither can pass.
    if not (low <= number <= high):
        return None
    return number


# ── Request-context channel ───────────────────────────────────────────────────
# The only context keys this agent accepts. Anything else is DROPPED before the
# graph is invoked: an undeclared key is not merely ignored by a validator — it
# travels on the context channel, the framework's first node returns that channel
# verbatim inside its own result, and the framework's output scan then fails the
# whole run with an error the caller cannot act on.
SUPPORTED_CONTEXT_KEYS: Tuple[str, ...] = ("channel",)

_MAX_CONTEXT_VALUE_CHARS = 64


def validate_context(context: Any) -> Tuple[Dict[str, str], List[Tuple[str, str]]]:
    """Reduce a caller context mapping to the supported, inert subset.

    Returns ``(accepted, refusals)``. Unknown keys are dropped rather than
    refused, because a dropped key cannot reach the channel the framework echoes
    back. ``refusals`` lists ``(reason, location)`` pairs for supported keys whose
    value cannot be accepted — the request cannot succeed with them, so the caller
    gets a reason it can act on instead of an opaque failure at the first node.
    """
    accepted: Dict[str, str] = {}
    refusals: List[Tuple[str, str]] = []
    if not isinstance(context, dict):
        return accepted, refusals

    for index, (key, value) in enumerate(context.items(), start=1):
        label = safe_field_label(key, index)
        if key not in SUPPORTED_CONTEXT_KEYS:
            continue
        if not isinstance(value, str):
            refusals.append((REASON_WRONG_TYPE, label))
            continue
        if len(value) > _MAX_CONTEXT_VALUE_CHARS:
            refusals.append((REASON_TOO_LONG, label))
            continue
        reason = screen_text(value)
        if reason:
            refusals.append((reason, label))
            continue
        normalised = normalise_identifier(value)
        if normalised is None:
            refusals.append((REASON_INVALID_IDENTIFIER, label))
            continue
        accepted[key] = normalised
    return accepted, refusals
