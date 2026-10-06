# Test Specification — RET-C2-256
## Retail Franchise Shift Handover Report

---

## 1. Overview

This document describes what the suite covers and why each part of it exists.

| Area | File | What it covers |
|------|------|----------------|
| Domain nodes | `tests/unit/test_agent.py` | The eight nodes, one class each |
| Caller screening | `tests/unit/test_input_guard.py` | Attacks refused AND ordinary text accepted |
| Output boundary | `tests/unit/test_output_boundary.py` | The credential invariant and the error envelope |
| Runtime configuration | `tests/unit/test_runtime_config.py` | Declared values reaching the backbone |
| End to end | `tests/integration/test_invoke_contract.py` | The real HTTP entry point and the real graph |
| Identity | `tests/integration/test_manifest_identity_alignment.py` | Entry point against the manifest |
| Boundaries | `tests/proof_of_boundary/` | Import isolation, state safety, backbone order, HITL |
| Framework compliance | `tests/unit/test_framework_compliance_tc06_tc07.py` | The security gates are not bypassable |

Two conventions run through all of it.

**Refusals are asserted behaviourally** — error status, nothing carried forward, and a reason
recovered from the closed set in `src/services/input_guard.py`. No test matches a node's
phrasing. A suite written against wording reports a regression when a message is reworded, and
keeps passing when a refusal turns into a pass with the same message.

**Screens are probed in both directions.** An over-eager screen refuses real work and no amount
of attack testing finds it, so every screen has a matching set of ordinary handover sentences
that must pass.

---

## 2. Test Environment

| Item | Value |
|------|-------|
| Framework | `agenticstar-agentcore` — the version the pipeline installs (`AGENTCORE_WHEEL_SPEC`) |
| Python | 3.11+ |
| Test runner | pytest 9.0.3 |
| State schema | `src/schemas/state.py` (flat TypedDict) |
| Graph | `RetailFranchiseShiftHandoverReportAgent` (outer) + `DomainWorkflowGraph` (inner) |

The suite runs without a platform connection. `emit_trace_event` is patched at each node's own
module namespace: the real audit sink needs a live backend, and without one it raises inside
`execute()`, the framework swallows the exception, and every assertion would silently be about
an error path instead of the agent.

---

## 3. Request Format

The agent accepts a JSON-encoded shift payload as `input` (`user_input` inside the graph).

### Schema

```json
{
  "store_id":    "inert identifier, <= 32 chars, e.g. LAWSON-7-001",
  "shift_date":  "YYYY-MM-DD",
  "shift_type":  "morning | afternoon | night (a _shift suffix is accepted)",
  "staff":       [{"staff_ref": "inert identifier", "role": "string", "hours_worked": number}],
  "sales":       {"total_yen": number, "transaction_count": number, "vs_target_pct": number},
  "incidents":   [{"type": "string", "severity": "LOW|MEDIUM|HIGH|CRITICAL",
                   "description": "string", "time": "string"}],
  "waste_items": [{"item_name": "string", "quantity_kg": number,
                   "category": "string", "disposal_method": "string"}]
}
```

### Bounds

| Field | Rule |
|---|---|
| `staff` / `incidents` | at most 50 entries |
| `waste_items` | at most 200 entries |
| `hours_worked` | finite, 0–24 |
| `total_yen` | finite, -1e11 – 1e12 |
| `transaction_count` | finite, 0 – 1e7 |
| `vs_target_pct` | finite, -100 – 1e4 |
| `quantity_kg` | finite, 0 – 1e4 |
| `item_name` / `description` / `role` / `time` | length-capped, then neutralised before rendering |
| whole request | at most 256 KB |

`staff[].name` is accepted for compatibility and is deliberately **not** carried forward. The
roster renders `staff_ref`, the role and the hours. See `docs/02_design.md` for why a personal
name cannot survive the round trip.

### Valid payload

The canonical request lives once, in `tests/fixtures.py` as `BASE_REQUEST`, and
`deploy/invoke_payload.json` is generated from it. `test_the_deployment_payload_comes_from_the_test_fixture`
holds the two together, so the deployment smoke check and this suite cannot end up asserting
different contracts.

```json
{
  "store_id": "LAWSON-7-001",
  "shift_date": "2026-07-07",
  "shift_type": "morning",
  "staff": [
    {"staff_ref": "st-0142", "role": "cashier", "hours_worked": 8},
    {"staff_ref": "st-0177", "role": "stocker", "hours_worked": 8}
  ],
  "sales": {"total_yen": 150000, "transaction_count": 300, "vs_target_pct": 5.0},
  "incidents": [],
  "waste_items": [
    {"item_name": "onigiri assorted", "quantity_kg": 2.5,
     "category": "prepared", "disposal_method": "compost"}
  ]
}
```

---

## 4. Test Cases

### 4.1 Domain nodes (`tests/unit/test_agent.py`)

| TC | Node | Input | Expected |
|----|------|-------|----------|
| TC-01 | InputParseNode | valid payload | SUCCESS, `shift_data` populated, identity fields set |
| TC-02 | InputParseNode | only `store_id` | ERROR, reason `missing_required_field`, no `shift_data` |
| TC-03 | InputParseNode | malformed JSON containing a secret | ERROR, reason `malformed_payload`, the input is not quoted back |
| TC-04 | InputParseNode | `shift_type: "overtime"` | ERROR, reason `invalid_identifier` |
| TC-04b | InputParseNode | `quantity_kg` of NaN / Infinity / negative / over-range / bool | ERROR, reason `not_a_finite_number` or `out_of_range` |
| TC-04c | InputParseNode | 201 waste items | ERROR, reason `too_many_entries` |
| TC-04d | InputParseNode | `store_id` with whitespace and heading characters | ERROR, reason `invalid_identifier` |
| TC-04e | InputParseNode | payload carrying `staff[].name` | SUCCESS, and `name` is absent from `shift_data` |
| TC-05 | AnomalyDetectNode | clean shift | SUCCESS, no findings, no escalation |
| TC-06 | AnomalyDetectNode | HIGH cooler alarm | `cooler_alarm` finding, escalation required |
| TC-07 | AnomalyDetectNode | shortfall just past the threshold, then far past it | MEDIUM, then HIGH — the severity moves with the number |
| TC-07b | AnomalyDetectNode | waste just under, then just over the threshold | no finding, then `waste_overrun` |
| TC-07c | AnomalyDetectNode | unreadable `quantity_kg` | an `unassessable` finding at HIGH — never silence |
| TC-07d | AnomalyDetectNode | empty roster | `understaffed` at CRITICAL |
| TC-08 | WasteFormatNode | one prepared-food entry | `regulatory_code` `SL-F02`, `total_kg` 2.5, no unreadable entries |
| TC-09 | WasteFormatNode | no waste items | empty log, `total_kg` 0.0 |
| TC-09b | WasteFormatNode | unreadable quantity | entry recorded and marked, excluded from the total |
| TC-09c | WasteFormatNode | `item_name` carrying newlines and heading characters | neither survives into the record |
| TC-10 | ReportGenerateNode | populated state | document contains 申し送り書, the store id and the grouped sales total |
| TC-10b | ReportGenerateNode | escalating vs clean shift | the escalation line appears only when required |
| TC-10c | ReportGenerateNode | roster carrying a personal name | no name and no redaction sentinel in the document; `staff_ref` present |
| TC-10d | ReportGenerateNode | incident description forging a section | exactly one waste section, one waste total, one escalation line |
| TC-11 | MultilingualAdaptNode | populated state | both language blocks present |
| TC-11b | MultilingualAdaptNode | three findings | rendered in detection order |
| TC-11c | MultilingualAdaptNode | non-numeric `vs_target_pct` | SUCCESS, and the value is not rendered |
| TC-12 | ResponseValidateNode | clean document | SUCCESS, `validated_output` set |
| TC-13 | ResponseValidateNode | document containing a credential | ERROR, output withheld, the value nowhere in the result |
| TC-12b | ResponseValidateNode | nothing to publish | ERROR |
| TC-12c | ResponseValidateNode | pass path / withhold path | `output_validated` / `output_withheld` audit event, payload free of the value |
| TC-14 | PreProcessNode | valid payload | SUCCESS, `validated_input` committed, identity hints set |
| TC-15 | PreProcessNode | empty, whitespace, non-string, oversized | ERROR with the matching closed-set reason |
| TC-15b | PreProcessNode | directive / control token / SQL / script / personal data / credential | ERROR with the matching closed-set reason |
| TC-15c | PreProcessNode | hostile field NAME | ERROR — keys are caller data too |
| TC-15d | PreProcessNode | the real payloads | SUCCESS — the screens do not fire on ordinary work |
| TC-16 | PostProcessNode | `validated_output`, then only `result` | the document is presented in both cases |

### 4.2 Trust levels

| Node | `required_trust_level` | Rationale |
|------|------------------------|-----------|
| `PreProcessNode` | `VERIFIED_EXTERNAL` | the outer caller gate, and the level the manifest declares |
| every inner domain node | `ANONYMOUS` | inner nodes inherit the outer caller's context |
| `PostProcessNode` | `ANONYMOUS` | downstream backbone node |

Inner nodes must be `ANONYMOUS` so a `VERIFIED_EXTERNAL` caller is not denied again at each
step of the inner pipeline.

### 4.3 Caller screening (`tests/unit/test_input_guard.py`)

37 hostile forms must be refused: prompt directives, chat-template control markers
(`<|...|>`, `[INST]`, `<<SYS>>`, `<s>`, `<system>`), a directive spliced across inline markup,
SQL, script and event-handler forms, personal-data shapes including a My Number written without
separators, and credential shapes from three different detectors.

16 ordinary handover sentences must NOT be refused, including two the earlier screen rejected:
*"Insert into stock room shelf 3 the returned bento"* and *"Update the set menu price tag at the
register"*.

Two properties are measured rather than assumed:

- `test_framework_detector_alone_would_be_narrower` — of the directive, SQL and script shapes
  this template refuses, the framework's detector scores only two as high confidence. Delegating
  to it would be a narrowing that looks like a tightening.
- `test_credential_screen_is_a_union_not_a_replacement` — the framework catches `AKIA`-shaped
  values that the template's patterns miss; the template catches `password=`-shaped values that
  the framework's miss; a forge token is caught by neither, which is why a third pattern exists.

The finite parser is driven with a per-field matrix: `"NaN"`, `"Infinity"`, `"-Infinity"`, raw
`float("nan")`, raw `float("inf")`, bools, non-numerics, and out-of-range magnitudes.

### 4.4 Output boundary (`tests/unit/test_output_boundary.py`)

`AgentBaseGraph.get_output` returns `formatted_output or result`, on error status too, so two
properties are asserted **separately**:

1. the refusal notice is truthy — otherwise the `or` falls back onto `result`;
2. `result` is empty — otherwise the fallback has the un-gated document to serve.

Splitting them is deliberate. A single assertion covering both would be satisfied by either
guard alone, and each would then be unfalsifiable.

The boundary is also driven **directly** rather than only end to end: the entry screen refuses
most credential shapes before the graph runs, so an end-to-end probe cannot tell a working
boundary from a boundary that is never reached.

### 4.5 End to end (`tests/integration/test_invoke_contract.py`)

Every case posts to `/invoke` on the real ASGI app with the real compiled graph:

- the deployment payload is accepted by the running agent;
- an unauthenticated caller is refused; an authenticated one reaches the declared trust level;
- a real document is produced from caller data, with the grouped sales total and the waste line;
- findings move with the input across three very different shifts;
- each escalation path is reachable, and the non-escalating path does not escalate;
- a refused request carries a closed-set reason and no document text;
- a non-finite number is refused end to end and no `nan`/`inf` appears in any output;
- the entry cap refuses volume a byte ceiling would admit;
- caller text cannot write a line of its own;
- an unsupported context key is dropped rather than carried; a credential-shaped one is refused
  with the field named and the value withheld;
- the same request renders the same findings order.

### 4.6 Proof of boundary

| Test | Checks |
|------|--------|
| `test_import_isolation.py` | no source file imports the platform SDK |
| `test_state_safety.py` | `State` carries no credential-like fields and no non-serialisable annotations |
| `test_pb_invoke_order.py` | a full invoke at `VERIFIED_EXTERNAL` runs the backbone in order and returns a non-empty output |
| `test_pb7_hitl_interrupt_propagation.py` | skipped — this agent does not enable human-in-the-loop |

---

## 5. Security Test Matrix

| Property | Where enforced | Test |
|---|---|---|
| Trust level at the caller boundary | `PreProcessNode` | TC-14/TC-15, and the end-to-end trust case |
| Directive, control-token, SQL and script screening | `src/services/input_guard.py` | 37 attack cases, both entry paths |
| Personal-data screening incl. unspaced Japanese | `src/services/input_guard.py` | `pii_*` cases |
| Credential screening (union of three detectors) | `src/services/input_guard.py` | `cred_*` cases + the union test |
| Finite and bounded numerics | `InputParseNode`, `AnomalyDetectNode` | the non-finite matrix + TC-07c |
| Structural caps | `InputParseNode`, adapter | TC-04c + the end-to-end cap cases |
| Caller text cannot forge document structure | `src/services/report_format.py` | TC-09c, TC-10d, the end-to-end forgery case |
| Credential invariant on the output | `ResponseValidateNode` | TC-13 + the boundary suite |
| Error envelope carries labels only | `ShiftHandoverGraphNode`, refusal sites | the containment suite |
| Audit trace on every boundary node | all `execute()` boundaries | TC-12c + `scripts/check_audit_trace.py` |
| Entry-point identity matches the manifest | `src/api/server.py` | `test_manifest_identity_alignment.py` |

---

## 6. Test Execution

```bash
pytest tests/ -v                      # everything
pytest tests/unit/ -v                 # nodes, screens, boundary, configuration
pytest tests/integration/ -v          # the real HTTP entry point
pytest tests/proof_of_boundary/ -v    # structural boundaries
```
