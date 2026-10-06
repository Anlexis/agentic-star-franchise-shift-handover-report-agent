# Template Design Specification — RET-C2-256

## Position in AgentCore Architecture

| Item | Value |
|---|---|
| Agent class | `RetailFranchiseShiftHandoverReportAgent` |
| L1 Base (framework base class) | `AgentBaseGraph` — direct framework inheritance |
| Inner graph | `DomainWorkflowGraph` (`BaseGraph`) |
| Pattern | Cat 2 nested — document generation |
| Generation mode | deterministic; no model is invoked anywhere in this template |

**Three-layer separation**

- State: flat TypedDict composition (no Pydantic — msgpack incompatible)
- Node: L1 inheritance, overriding `execute(self, state, config=None) -> dict` only
- Graph: composition, via `register_nodes()`

## Architecture Overview

### Use case

A franchise convenience store produces a handover document for its incoming shift. One
structured request describing the shift becomes a Japanese handover document (申し送り書), a
food-waste log in the regulatory reporting format used under Japan's Act on Promotion of Food
Loss Reduction, and a short bilingual summary for staff who do not read Japanese fluently.

### Outer backbone (fixed — `add_edges()` is not overridden)

```
START → initialize → pre_process → main → {route} → post_process → finalize → END
                                        ↓ (RETRY, bounded by max_retry)
                                     pre_process
```

`route` is the framework's. It sends SUCCESS to `post_process` and **every error status
straight to `finalize`** — which is why `post_process` is not on the failure path and cannot be
where containment lives. See *The error envelope* below.

### Inner domain workflow (`DomainWorkflowGraph`)

```
START
  → input_parse        (InputParseNode)        parse and bound the request
  → anomaly_detect     (AnomalyDetectNode)     derive the findings
  → waste_format       (WasteFormatNode)       build the regulatory waste log
  → report_generate    (ReportGenerateNode)    render the Japanese document
  → multilingual_adapt (MultilingualAdaptNode) render the bilingual summary
  → response_validate  (ResponseValidateNode)  the output boundary
  → END
```

### Node configuration

| Node | Responsibility | Trust level | Reads | Writes |
|------|---------------|-------------|-------|--------|
| initialize | schema_version, session_id, trust_level | framework default | — | schema_version, session_id |
| pre_process | trust gate + input screening, identity hints | VERIFIED_EXTERNAL | user_input | validated_input, store_id, shift_date, shift_type, status |
| main (`ShiftHandoverGraphNode`) | delegate to the inner graph; own the error envelope | GraphNode (no gate) | validated_input | result, formatted_output, status |
| post_process | present the finished document | ANONYMOUS | validated_output, result | formatted_output, status |
| finalize | response_metadata, total_time_ms | framework default | — | response_metadata |
| input_parse | parse and bound every field | ANONYMOUS | validated_input | shift_data, identity fields, status |
| anomaly_detect | derive findings and the escalation flag | ANONYMOUS | shift_data | anomalies, escalation_required, status |
| waste_format | build the regulatory waste log | ANONYMOUS | shift_data | waste_log, status |
| report_generate | render the Japanese document | ANONYMOUS | shift_data, anomalies, waste_log | shift_report, status |
| multilingual_adapt | render the bilingual summary | ANONYMOUS | shift_data, anomalies, waste_log | bilingual_summary, status |
| response_validate | the output boundary | ANONYMOUS | shift_report, bilingual_summary | validated_output, status |

### Supporting modules

| Module | Responsibility |
|--------|----------------|
| `src/services/input_guard.py` | every caller screen, the finite parser, the inert-identifier shape, the closed set of refusal reasons |
| `src/services/report_format.py` | the document's structural vocabulary, the sanitiser that keeps caller text out of it, and the refusal envelope |
| `src/services/runtime_config.py` | the single reader of `config/config.yaml` |

### Data flow

```
input (JSON) → adapter: authenticate, size, screen, reduce the context
  ↓ pre_process — trust gate, screens, identity hints
validated_input
  ↓ input_parse — bounds, caps, finite numerics
shift_data
  ↓ anomaly_detect → anomalies + escalation_required
  ↓ waste_format   → waste_log
  ↓ report_generate → shift_report
  ↓ multilingual_adapt → bilingual_summary
  ↓ response_validate — the credential invariant
validated_output → result → formatted_output → finalize → response
```

## Design Decisions

| Decision | Alternative | Chosen | Rationale |
|----------|-------------|--------|-----------|
| L1 base type | AutonomousBaseGraph | AgentBaseGraph | a fixed pipeline; no autonomous loop |
| Composition | Cat 1 flat | Cat 2 nested | six domain steps is too much for a single main slot |
| Inner trust level | INTERNAL | ANONYMOUS | inner nodes inherit the caller's context; INTERNAL would deny real callers at every step |
| Output boundary location | PostProcessNode | ResponseValidateNode (last inner) | the domain invariant belongs to the domain pipeline, and post_process is not on the failure path |
| Subgraph error strategy | propagate | contain | see *The error envelope* |
| Roster identification | personal names | inert `staff_ref` | see *Personal names* |
| Multilingual target | Japanese + English | Japanese + Vietnamese + English | the largest foreign-worker language groups in convenience-store operations |
| Monetary precision | round rendered totals to a grid | render as given | see *Monetary values* |

### The error envelope

`AgentBaseGraph.get_output` returns `state["formatted_output"] or state["result"]`, and it does
so on error status as well as on success. That makes the error path a caller-visible channel
with a fallback in it, and two rules follow:

1. a refusal must write a **truthy** notice, or the `or` falls through to `result`;
2. a refusal must **empty** `result`, or the fallback has the un-gated document to serve.

Both are implemented in `report_format.contained_refusal()` and applied at every refusal site.
The notice is assembled from closed-set labels only — a reason code and, when it is inert, a
field location. Nothing node-authored is re-emitted: `error_log` carries node text and,
wherever a node interpolates a caught exception, an upstream message body, so truncating or
redacting it would not be a closed error contract. `error_log` is not projected today, which is
a reason to keep it clean rather than a reason to relax it.

`ShiftHandoverGraphNode.error_strategy` is `"contain"` rather than the framework default
`"propagate"`. With `"propagate"` the framework raises before `merge_output()` is reached, the
node wrapper catches it and returns a bare error partial, and the caller receives `output: null`
with no reason anywhere. Containing routes both failure paths — an inner error status and an
inner exception — through `on_subgraph_error()`, which is the one place this agent can state a
reason the caller can act on.

One failure mode is outside the graph's reach: the framework's own input gate refuses some
payloads before any template code runs, and that path also returns a bare partial. The HTTP
adapter therefore screens the request with the same composition the entry node uses and answers
`400` with the closed-set reason. The request cannot succeed either way, so the choice is
between an actionable refusal and an opaque one. This does not replace the node's screen: when
the platform gateway calls `invoke()` directly the adapter is not in the path at all.

### Personal names

The platform's input filter rewrites values it classifies as personal data before any template
code runs. A roster naming a person in romanised form arrives as the redaction sentinel, and the
document would name a staff member `[MASKED]`; the same name written in Japanese passes through
unmasked. The document would be simultaneously useless and disclosing, depending on how a name
happened to be spelled.

The roster therefore renders an inert `staff_ref`, the role and the hours. That is
identification which survives the round trip intact, and it removes a free-text field from a
structured document — which is the second reason: any caller string that reaches this document
is a string that could try to write part of it.

### Caller text in a structured document

The document's structure is carried entirely by a small set of characters — the rules, the
heading brackets, the bullet, the escalation mark and the ideographic indent. A caller string
containing any of them, a newline above all, can write a line that reads as ours. Driven through
the real graph, one incident description produced three copies of the regulatory food-waste
section, one of them reporting a total of 0.000 kg, and three copies of the escalation line,
inside a success envelope.

`report_format.render_safe()` neutralises control characters and the structural vocabulary,
collapses whitespace, and bounds the length; Unicode format and control categories are removed
wholesale rather than enumerated, so a bidirectional override cannot be used to make one line
read as another. Rendered caller text is additionally quoted where it shares a line with the
document's own prose. Both sides import the vocabulary from one module, because two copies would
drift and a drifted sanitiser passes everything.

### Numbers

Every caller-controlled number goes through one finite and bounded parser and fails closed.
`NaN` and `Infinity` parse out of a JSON body and through `float()`, and every comparison
against `NaN` is false — so a non-finite waste quantity passed the overrun check that the
findings step exists to make, and reported `nan kg` in a regulatory log while returning success.
Where a number cannot be read, the findings step raises an `unassessable` finding at HIGH rather
than reporting silence: "cannot say" must not render as "nothing found".

### Monetary values

This template renders monetary figures — the shift's own sales total — back to the operator who
supplied them, and states no rounding invariant. The precision grid some templates enforce on an
externally-facing report is therefore **not applicable** here: rounding a store's own sales
figure would make the handover document wrong for its only purpose. The invariant this template
does state is the credential one below, and that is what the output boundary enforces.

## Security Design

| Concern | Where | Implementation |
|---------|-------|----------------|
| Caller trust | `PreProcessNode` | `required_trust_level = VERIFIED_EXTERNAL`, matching the manifest; the adapter establishes it from a bearer credential |
| Input screening | `src/services/input_guard.py` | directive, SQL and script patterns; chat-template control markers as a class; personal-data shapes; credential shapes — raw and markup-stripped, depth-first over the parsed payload including keys |
| Bounds | `InputParseNode` | entry caps, length caps, finite ranges per field; refusals name a field and a closed-set reason and never quote the value |
| Output invariant | `ResponseValidateNode` | credential scan; on violation, error status plus every output-bearing field emptied |
| Audit | every `execute()` boundary | `emit_trace_event(event, payload, state)` with closed-set payloads |
| Secrets | entry point | provisioned under the identity the manifest declares; nothing in State; `requires.secrets` is empty because nothing requires one |

### Detector composition

Every screen is the **union** of the framework's detector and this template's own patterns.
Neither is a superset of the other, measured against the installed SDK:

| Shape | Template patterns | Framework detector |
|---|---|---|
| `password=` / `api_key:` / `Authorization:` / `user:pass@host` | refuse | pass |
| `AKIA…` / `sk_live_…` / `sk-…` / JWT | pass | refuse |
| forge access tokens | pass | pass |
| directive, SQL, script forms | refuse (19 patterns) | 2 of 13 scored high |

Replacing either side with the other narrows the gate while looking like a tightening. The third
row is why a third pattern set exists: a forge-token-shaped value in an incident description was
returned verbatim to the caller inside a success envelope, because neither detector carried that
shape.

A screen narrower than the framework's is worse than merely incomplete: the framework raises on
the value anyway, but it raises inside the node wrapper, which discards the node's delta and any
containment it performed.

### Screens must not fire on real work

Two of the inherited SQL patterns matched ordinary retail sentences — *"Insert into stock room
shelf 3 the returned bento"* and *"Update the set menu price tag at the register"* — in a retail
template. Both are now anchored on statement context, and both sentences are pinned as tests. An
over-eager screen is the failure mode no amount of attack testing finds.

## Import Isolation

- No platform SDK import anywhere in `src/`
- Import targets: `framework.*` and `shared.*` only
- Enforced by `tests/proof_of_boundary/test_import_isolation.py`

## Configuration

`config/agent.yaml` is the static manifest: identity, namespace, entry point, trust level and
the compile-time `requires` gates. It holds no runtime values.

`config/config.yaml` holds the runtime values and has exactly one reader,
`src/services/runtime_config.py`. The entry point passes them as `Graph(config=...)`, so
`max_retry` reaches the framework's own routing decision; every value is bounds-checked on load,
so an out-of-range or non-finite entry degrades to the documented default rather than silently
changing behaviour.
