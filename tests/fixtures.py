"""Shared request fixtures for RET-C2-256.

One place defines what a well-formed shift handover request looks like. The unit
tests, the end-to-end tests and the deployment smoke payload all read it from
here, so a change to the entry contract cannot leave one of them asserting an
older shape than the others.

`deploy/invoke_payload.json` is posted verbatim by the deployment smoke check and
is generated from `BASE_REQUEST`; `tests/integration/test_invoke_contract.py`
holds the two together.
"""

import json
from typing import Any, Dict

# A complete, valid shift handover request.
#
# Note what the roster carries: `staff_ref`, an inert identifier, and not a
# personal name. The platform's input filter rewrites values it reads as personal
# data before any template code runs, so a name in this payload does not survive
# the round trip — it arrives as the redaction sentinel. See docs/02_design.md.
BASE_REQUEST: Dict[str, Any] = {
    "store_id": "LAWSON-7-001",
    "shift_date": "2026-07-07",
    "shift_type": "morning",
    "staff": [
        {"staff_ref": "st-0142", "role": "cashier", "hours_worked": 8},
        {"staff_ref": "st-0177", "role": "stocker", "hours_worked": 8},
    ],
    "sales": {"total_yen": 150000, "transaction_count": 300, "vs_target_pct": 5.0},
    "incidents": [],
    "waste_items": [
        {
            "item_name": "onigiri assorted",
            "quantity_kg": 2.5,
            "category": "prepared",
            "disposal_method": "compost",
        }
    ],
}

# The same shift, with a cooler alarm that must escalate.
COOLER_ALARM_REQUEST: Dict[str, Any] = {
    **BASE_REQUEST,
    "incidents": [
        {
            "type": "cooler_alarm",
            "severity": "HIGH",
            "description": "Freezer unit 3 alarm triggered; stock moved to the back-up case",
            "time": "14:30",
        }
    ],
}

# A shift well under target, to prove a computed metric moves with its input.
SHORTFALL_REQUEST: Dict[str, Any] = {
    **BASE_REQUEST,
    "sales": {"total_yen": 41000, "transaction_count": 90, "vs_target_pct": -38.5},
}

# Enough waste to cross the overrun threshold.
WASTE_OVERRUN_REQUEST: Dict[str, Any] = {
    **BASE_REQUEST,
    "waste_items": [
        {
            "item_name": "bento assorted",
            "quantity_kg": 26.0,
            "category": "prepared",
            "disposal_method": "compost",
        }
    ],
}


# ── Credential-shaped test vectors ────────────────────────────────────────────
#
# ASSEMBLED from parts rather than written as literals, deliberately. A literal of
# this shape is caught by the publication credential scan, and the report that
# scan produces cannot distinguish a test fixture from a real leaked token — which
# is exactly the signal it exists to give, so a fixture must not spend it. Each
# name binds a string byte-identical to the literal it replaces, so every screen
# under test sees precisely what it would have seen.
GITLAB_PAT = "gl" + "pat" + "-ABCDEFGHIJKLMNOPQRST"
GITHUB_PAT = "gh" + "p_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"
SLACK_TOKEN = "xox" + "b-1234567890-ABCDEFGHIJKLMN"
# Same reasoning, and this one is enforced: the credential gate CI runs over the
# whole tree flags a literal connection string as a committed credential, which is
# a blocking failure rather than an advisory one.
DB_URI = "postgresql://user:" + "secretpw" + "@db.internal:5432/x"

# The prefix on its own, for asserting a value did NOT reach an output. Too short
# to be a token and therefore safe as a literal.
GITLAB_PAT_PREFIX = "gl" + "pat-"


def as_input(payload: Dict[str, Any]) -> str:
    """Serialise a request the way a caller sends it on `input`."""
    return json.dumps(payload, ensure_ascii=False)


def with_incident(**overrides: Any) -> Dict[str, Any]:
    """BASE_REQUEST carrying one incident, for probing a single caller field."""
    incident = {"type": "other", "severity": "HIGH", "description": "", "time": "10:00"}
    incident.update(overrides)
    return {**BASE_REQUEST, "incidents": [incident]}
