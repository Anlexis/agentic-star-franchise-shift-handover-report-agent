# Franchise Shift Handover Report Agent

AI agent for generating franchise store shift handover reports, built with Agentic Star.

> **Category**: Cat 2 (domain pipeline — structured document generation)
> **Industry**: Retail
> **Template ID**: RET-C2-256

## Overview

Generates the shift handover document a franchise convenience store passes to its incoming
shift. From one structured request describing the shift — roster, sales, incidents and food
waste — it produces three things:

- a Japanese handover document (申し送り書) covering the roster, sales against target, the
  findings that need attention, and the food-waste log;
- a food-waste log in the regulatory reporting format used under Japan's Act on Promotion of
  Food Loss Reduction;
- a short bilingual summary, Japanese and Vietnamese/English, for staff who do not read
  Japanese fluently.

Findings are derived rather than copied: cooler and equipment alarms, an understaffed shift,
sales below the shortfall threshold, high-severity incidents and waste above the overrun
threshold each raise a finding, and any HIGH or CRITICAL finding marks the handover for
escalation to the store manager.

No language model is involved. Every output is computed from the request, so the same request
produces the same document.

This is an agent template built with the **AGENTIC STAR** development platform and the
**AgentCore Framework**. It is intended to be taken as a starting point: fork it, adapt it to
your own data and policies, and run it inside your own AGENTIC STAR deployment.

## Requirements

**This template does not run standalone.** It requires:

| Requirement | Notes |
|---|---|
| **AGENTIC STAR platform** | The agent connects to the platform at start-up. Without it, start-up fails immediately (see *Behaviour without the platform* below). Deployment guides and API documentation: [AGENTIC STAR Developers](https://developers.fd.agenticstar.tm.softbank.jp/) |
| **AgentCore Framework** (`agenticstar-agentcore`) | Installed from PyPI as a dependency. |
| Python | >=3.11 |

```bash
pip install -e .
```

### Behaviour without the platform

The framework is designed to run **only** on AGENTIC STAR. There is no fallback or degraded
mode: if the platform is unreachable or the SDK version does not match, the agent fails during
graph compile or start-up preflight rather than starting in a partially working state. This is
intentional — a half-running agent is worse than one that refuses to start.

## Request format

`POST /invoke` takes a JSON-encoded request on `input`:

```json
{
  "store_id": "LAWSON-7-001",
  "shift_date": "2026-07-07",
  "shift_type": "morning",
  "staff": [{"staff_ref": "st-0142", "role": "cashier", "hours_worked": 8}],
  "sales": {"total_yen": 150000, "transaction_count": 300, "vs_target_pct": 5.0},
  "incidents": [
    {"type": "cooler_alarm", "severity": "HIGH", "description": "...", "time": "14:30"}
  ],
  "waste_items": [
    {"item_name": "onigiri assorted", "quantity_kg": 2.5,
     "category": "prepared", "disposal_method": "compost"}
  ]
}
```

Two things about this contract are worth knowing before you adapt it.

**Staff are identified, not named.** The roster carries `staff_ref`, an inert identifier, and
the document renders that with the role and the hours. Personal names are not rendered. The
platform's input filter rewrites values it classifies as personal data before any template code
runs, so a name does not survive the round trip intact; and a free-text field that reaches a
structured document is a field a caller can write document structure into.

**Every number is bounded and must be finite.** `NaN` and `Infinity` parse out of a JSON body
and through `float()`, and every comparison against `NaN` is false — so a non-finite waste
quantity would pass the overrun check silently. Numbers outside their declared range, and
values that are not finite, are refused with the field named.

Requests are refused with a reason code from a closed set — `not_a_finite_number`,
`too_many_entries`, `credential_shape` and so on — and a field location. The rejected value is
never echoed back.

## Quick Start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python -m pytest tests/ -v
```

Tests run without a platform connection. Running the agent itself does not.

## Project Structure

```
src/          agent implementation (nodes, services, schemas)
tests/        unit, integration and boundary tests
config/       agent manifest and runtime configuration
docs/         design documentation and test specification
```

`docs/02_design.md` describes the architecture and the security boundaries;
`docs/03_test_spec.md` describes the request contract and the test cases.

## Customising

1. Adjust `config/config.yaml` for your own environment and policies.
2. Adapt the thresholds in `src/nodes/anomaly_detect_node.py` — staffing minimum, sales
   shortfall, waste overrun — to your own operation.
3. Adapt the regulatory category mapping in `src/nodes/waste_format_node.py` to the reporting
   format you file under.
4. Adapt the document layout in `src/nodes/report_generate_node.py`. If you add structural
   characters, add them to `src/services/report_format.py` as well — that module is what stops
   caller text writing a line that looks like one of yours.
5. Re-run the test suite.

## License

MIT — see [LICENSE](LICENSE).

## Status of this repository

This template is published **as is**, by its individual author, under the MIT license. It carries
**no warranty and no support commitment**, and no organisation stands behind its behaviour or
fitness for any purpose. Issues and pull requests may or may not receive a response; that is at
the sole discretion of the repository owner.
