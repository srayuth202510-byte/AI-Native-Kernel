# Pivot: AI-Native Kernel → AI Infrastructure Security Platform

> Status: **accepted — in execution.** Committed 2026-09; Phase 1 steps 1–8 of §7
> are shipped. Supersedes the "AI agent kernel" positioning in `README.md` /
> `docs/ai_native_kernel_plan_v2.html`. The kernel code is **retained**, not replaced.
>
> Step-to-task mapping and current state live in `docs/tasks.json` (ANK-060..067) and
> `README.md` §9. This document remains the rationale for *why*; those two track *what*.

## 1. Thesis

The project already contains a credible AI-infrastructure security substrate and almost
no market-facing product. The pivot is therefore **not** a rewrite — it is a change of
*plane* plus the addition of a data plane.

Today the system enforces at the **host plane**: eBPF/LSM hooks (`lsm/file_open`,
`lsm/bprm_check_security`, `lsm/socket_create`) gate what a *process* may do. That is a
real asset, but it is invisible to the buyers of AI infrastructure, whose failures happen
at the **data plane**: a prompt that carries an injection, a response that leaks PII, a
client that is systematically extracting the model.

**The wedge: nobody credible does both.** Application-layer LLM firewalls die the moment
the inference server is RCE'd. Host-layer security is structurally blind to prompt
injection. We can be the only product that enforces the *request* and the *process* under
one audit chain and one policy model.

### What we explicitly refuse to do

We will **not** build a transformer-grade prompt-injection classifier. That market is
held by Lakera, Robust Intelligence, and Mindgard, who have labelled datasets and model
teams. `kernel-companion/src/nlp.rs` (380 lines, cosine similarity over djb2 word hashes)
is an *intent router* and cannot be promoted into a security classifier — hash embeddings
are defeated by whitespace obfuscation and simple paraphrase, both of which are trivial
for an attacker. Losing that comparison would consume the entire roadmap.

Phase 1 is scoped to the two controls that need **no classifier at all** (§6).

## 2. Two-plane architecture

```
                       ┌─────────────── control plane (existing, unchanged) ───────────────┐
                       │  ank-cli ──UDS──▶ kernel-companion ──▶ PolicyEngine / AuditLogger  │
                       │                   (PeerCredentials + session tokens)              │
                       └───────────────────────────────┬───────────────────────────────────┘
                                                       │ scope, thresholds, revocation
   client (SDK/CI/agent)                              ▼
        │  OpenAI-compatible                    ┌──────────────┐
        ├───────────────▶ ┌──────────────┐      │ ai-gateway   │  ◀── NEW: axum, TLS, SSE
        │   Bearer/JWT   │ semantic-    │─────▶│ (data plane) │
        │                │ guard        │      └──────┬───────┘
        │                └──────────────┘             │ reqwest passthrough
        │                                           ▼
        │                                    vLLM / TGI / Ollama  ◀── launched under
        │                                    (host plane)              ank-run scope
        ▼
   audit chain (chained_log, sharded per tenant)
```

The inference server is launched via `ank-run` so that a compromised or exploited model
server is still confined by the LSM gate. That is the differentiator, and it is already
built.

## 3. Asset map — what we keep, and in what role

| Existing code | New role | Action |
|---|---|---|
| `capability-security/src/audit.rs` | Tamper-evident evidence for every API decision | **Refactor** — extract chain mechanics (§5). Do not extend the struct. |
| `capability-security/src/policy.rs` | Fail-closed principle | Keep for host plane. **Do not reuse** for data plane (§4). |
| `capability-security/src/uds_auth.rs` | Admin/control auth (token file, session TTL, capability map) | Keep. Pattern is correct. |
| `capability-security/src/token.rs` | Host-plane identity | Keep, host plane only. |
| `immune-system/src/tcell.rs` | Per-tenant rate/anomaly detection, revocation | **Adapted** — now keyed by `tenant_id` (`DashMap<String, TenantState>`); PID retained for quarantine/kill actions. |
| `kernel-companion/src/ebpf/lsm-security.bpf.c` | Host-plane enforcement of the model server | Keep, unchanged. |
| `kernel-companion/src/metrics_server.rs` | Prometheus/OTel | Keep. |
| `compute-scheduler/src/vllm.rs` | Existing vLLM client — becomes the passthrough backend | Keep. |
| `context-memory` (Qdrant/warm tier) | Vector store under audit | Later phase. |
| `agent-scheduler`, `compute-scheduler`, `intent-bus` | Agent runtime | **Deprioritize** — not on the AI-infra critical path. |

### Why `AuditEntry` must not be extended

`AuditEntry` (`audit.rs:32`) is syscall-shaped: `pid`, `uid`, `syscall`, `anomaly_score`.
An API decision has none of those, and forcing them into `reason` is a lossy hack that
will corrupt the audit semantics within two quarters.

Worse, `compute_hash` (`audit.rs:61`) hashes the serialized struct, so **adding a field
changes every hash and invalidates every existing log**. Existing deployments would fail
`validate_log` (`audit.rs:345`) the moment the binary is upgraded. Existing logs must
keep validating forever.

**Decision:** the gateway gets its own entry type in a new crate, sharing only the chain
mechanic.

## 4. Why the data plane needs a new authorization model

`Scope` is `Process(u32) | Thread(u32) | Global` (`token.rs:71`) — it is *process identity*.
It cannot express "tenant A may call model X on `/v1/chat/completions` but not
`/v1/embeddings`." `PolicyEngine` is a `HashSet<String>` allowlist plus a default decision
(`policy.rs:19`); it has no attributes, no tenant, no rate, no time window, and no reason
codes. `authorize` returns `bool` (`policy.rs:49`) — useless to a client that needs to know
*why* it was denied.

A gateway needs a decision that carries a reason, so the data plane gets its own model:

- **Identity**: tenant (from Bearer/JWT, verified), plus per-tenant key id.
- **Resource**: model, endpoint, and (later) vector collection.
- **Decision**: `Verdict { Allow | Deny | AllowRedacted }` **with a reason code** — this is
  what gets returned to the client and written to the chain.
- **Attributes**: rate window, token budget, PII policy, concurrent-request ceiling.
- **Default**: DENY, matching the existing house rule.

Reuse the *principle* (fail-closed, audited, constant-time) — not the type.

## 5. Required refactor: `chained_log`

`AuditLogger::record` (`audit.rs:258`) holds a single `Arc<tokio::sync::Mutex<Option<File>>>`
(`audit.rs:160`) across the *entire* operation — tail-read previous hash, SHA-256, write,
**and flush**. Every audit write in the process is serialized on one mutex, including
blocking `fsync`-adjacent flush latency.

For a syscall-level companion this is irrelevant: a few writes per second. For a gateway
in front of an inference server it is a hard ceiling — this becomes the throughput limit
of the whole product, and it is a lock convoy, not a disk problem.

Plan:

1. Extract the chain mechanics into a generic `chained_log::ChainedLog<E>` — tail-read
   (`audit.rs:176`), newline repair after crash (`:228`), write/flush, hash-cache
   invalidation on failure (`:317`). All of it is already generic over "entry with a hash"
   in practice; it just was never parameterized.
2. `AuditLogger` becomes `ChainedLog<AuditEntry>`. **Zero behavior change.** Existing
   tests in `audit.rs` (round-trip, tail-read, tamper detection) become the regression
   suite proving the refactor is sound.
3. The gateway uses **per-tenant chains** (sharded `ChainedLog`), so no single mutex is
   global. Cross-shard ordering is not needed for tamper evidence; each shard's chain is
   independently verifiable. A `chain_id` field on the entry ties shards into one queryable
   timeline.

This refactor is the highest-leverage single change in the pivot and is a prerequisite for
Phase 1.

## 6. Phase 1 scope

### In

1. **`crates/ai-gateway`** — axum + hyper, TLS termination, OpenAI-compatible
   `/v1/chat/completions`, `/v1/completions`, `/v1/embeddings`, plus `/healthz`.
   Bearer/JWT tenant auth. Streaming SSE passthrough.
2. **`crates/semantic-guard`** — deliberately thin, and honest about it:
   - **PII detection + redaction** on request *and* response. Regex/entropy for emails,
     keys, card numbers, national IDs. Returns `AllowRedacted`. This is genuinely
     tractable without a model, and it is what enterprises buy first.
   - **Known-injection-pattern matcher** — curated signatures, Unicode-normalized, with
     homoglyph/great-whitespace folding to blunt the trivial bypasses. Shipped
     `detection_mode = "signature"` in metrics so nobody mistakes it for a classifier.
3. **`crates/extraction-det`** — model-theft detection. High-signal, model-free signals:
   query rate, per-tenant token burn, systematic prefix/suffix enumeration, and
   near-duplicate prompt clustering (MinHash over normalized prompts). Extraction is a
   *statistical* pattern, so this works without semantic understanding.
4. Every decision → per-tenant `ChainedLog`, sharded.
5. `ank verify-audit` — CLI subcommand to run `validate_log` over a chain and emit
   evidence. Turns the audit chain into a *product feature* (compliance export), not an
   internal log.

### Out (explicitly deferred)

- Transformer/embedding-based injection detection — Phase 2, and only behind a pluggable
  interface so a customer can bring their own model.
- RAG / vector-store poisoning detection — Phase 2.
- Multi-node, HA, control plane federation — Phase 3.
- Rebranding, docs rewrite, marketing site — do this **after** the gateway carries real
  traffic, so the positioning is written against a working demo.

### Latency budget (binding)

`AGENTS.md` sets LSM decision P99 < 1 ms. A gateway hop must not eat inference latency.
Therefore:

- Request path: inspect fully (bounded at 256 KB), then stream.
- Response path: inspect headers + a bounded prefix (first 4 KB). Full-response inspection
  is **not** compatible with SSE streaming and is out of scope. If prefix inspection fails
  for any reason (guard error, budget overrun), the stream terminates with an error and the
  buffered prefix is withheld — never released as "clean". A `Deny` verdict on a response
  likewise returns an error (403), never the denied body with a flag attached.
- Guard budget: P99 < 2 ms added. Enforced **after the fact** — `check_budget` compares
  elapsed time at each stage boundary (`semantic-guard/src/lib.rs`) and returns
  `GuardError::BudgetExceeded`, so an overrun is detected but the stage that overran has
  already run. This is not a preemptive interrupt, and it is not a `tokio::time::timeout`.
  A guard that exceeds budget **fails closed** per the house rule, and the timeout itself is
  audited — otherwise "fail closed" silently becomes "deny everything" during an incident.

### Measured (release build, 2,000 samples per layer)

`crates/ai-gateway/tests/perf_budget.rs` — `cargo test -p ai-gateway --release --test
perf_budget -- --nocapture --test-threads=1`. Numbers are on this dev box, not a vLLM host;
treat them as a regression tripwire, not as a published benchmark. P99 varies run to run
(observed across runs: CPU-only path 10.3–12.2 µs, full request path 36–52 µs), so the
ordering of layers is the durable result, not the third digit.

| Layer | P50 | P99 | Max |
|---|---|---|---|
| auth + authorize | ~0.28 µs | ~0.30 µs | ~1 µs |
| request summary parse (JSON) | ~0.74 µs | ~1.16 µs | ~10 µs |
| guard, clean text | ~1.93 µs | ~2.03 µs | ~101 µs |
| guard, PII redaction | ~4.48 µs | ~4.69 µs | ~241 µs |
| extraction-det `observe` | ~1.86 µs | ~2.49 µs | ~10 µs |
| CPU layers only (no audit write) | ~5.9 µs | ~11.8 µs | ~206 µs |
| **`inspect_request`, everything incl. audit write** | **~23 µs** | **~36–52 µs** | **~380–550 µs** |

The last row is the one that matters: `inspect_request` is what the handler actually calls,
and it writes the per-tenant audit chain **inline** — `record_audit().await` is on the request
path, not spawned to a background task, and it fails closed if the write fails. Audit write
costs ~17–40 µs on top of the CPU-only path (measured as the delta between the last two rows),
so the full request path sits ~40x under the 2 ms budget even at the worst P99 observed
across runs.

Caveats: the redaction path is ~2.2x the clean path because it allocates and copies a
rewritten string; the max outliers (~100–550 µs) are scheduler noise on a shared dev box, not
guard work; and `ChainedLog` calls `flush()` without `fsync`, so these numbers cover a
page-cache write, not durable-to-disk — on a slow or loaded volume the tail will move.
Concurrent tenants do not block each other (per-tenant `DashMap` shard + per-chain mutex), but
concurrent requests *to the same tenant* serialize on that chain lock, which is not exercised
by this single-stream test.

## 7. Migration order

Each step is independently shippable and independently revertable.

| # | Step | Task | State | Gate |
|---|---|---|---|---|
| 1 | Extract `chained_log`, rebase `AuditLogger` on it | ANK-060 | ✅ | Existing `audit.rs` tests pass unchanged; `validate_log` still accepts pre-refactor logs |
| 2 | Add `extraction-det` as a library with unit + property tests | ANK-061 | ✅ | Rate/volume logic tested with `proptest`; no gateway needed yet |
| 3 | Add `semantic-guard` PII + signature engine | ANK-062 | ✅ | Corpus in `tests/fixtures/`; adversarial redaction fixtures (unicode, zero-width) |
| 4 | Add `ai-gateway` pass-through, no guard | ANK-063 | ✅ | OpenAI-SDK conformance test against a mock upstream; SSE frame-for-frame |
| 5 | Wire guard + extraction-det + sharded audit into the gateway | ANK-064 | ✅ | End-to-end: denied request appears in the chain, `verify-audit` passes |
| 6 | Adapt `tcell.rs` to tenant keys | ANK-065 | ✅ | `DashMap<tenant, TenantState>`; rate/anomaly per tenant, quarantine per PID; `uid_to_tenant` mapping in config |
| 7 | `ank verify-audit` + audit export | ANK-066 | ✅ | Same JSON schema on both planes (`capability_security::verify_report`); golden-shape test pins field names |
| 8 | Reposition docs/README | ANK-067 | ✅ | — |

On step 7, verification is done (`ank-cli verify-audit <file>` for the host plane,
`ai-gateway verify-audit --dir <dir>` across every data-plane shard) and SIEM export is
done too: both commands accept `--format json` / `--output <path>` and emit the same
`VerifyReport` schema from `capability_security::verify_report`, verified through the
single `ChainedLog::validate` implementation rather than a re-implemented walk.

Steps 1–3 are pure library work with no network surface, so they are cheap to build,
testable in CI without root or eBPF, and they de-risk the whole pivot before we commit to
an axum/TLS/SSE stack.

## 8. What would kill this

Stated up front so we can watch the signals:

1. **Latency.** If the added P99 exceeds ~2 ms in a real vLLM deployment, buyers reject it
   regardless of features. **Measured** — see "Measured" above: the full `inspect_request`
   path including its inline audit write is 36–52 µs P99 in release, ~40x under budget at the
   worst observed run, and the
   per-layer tests assert that budget on every release run. The CI stage runs it as
   `required` since 2026-10-02 (buyer decision §9.1) — a regression blocks the merge.
   If shared-runner noise ever flakes it, revert to `non-blocking` only with evidence
   attached, not silently. Still not validated against a real vLLM host with TLS and
   concurrent tenants, which is where the tail could still move.
2. **The PII/signature layer gets dismissed as "just regex."** It probably will be. The
   answer is the host plane — the regex layer is the on-ramp, not the pitch.
3. **eBPF/LSM deployment friction.** Requiring privileged, kernel-specific setup to get
   value is a real adoption tax. The gateway must be fully useful *without* the LSM layer
   loaded; the kernel plane is defense-in-depth for those who can run it.
4. **Tunnel/indirect-prompt blind spots.** A signature matcher will miss genuinely novel
   injections. Ship `detection_mode` telemetry and per-tenant tuning so operators can see
   coverage instead of believing a guarantee we cannot make.

## 9. Buyer decision (locked 2026-10-02)

**Buyer: the AI platform team** — the team that runs inference infrastructure (vLLM/TGI/
Ollama fleets, gateways, tenants) and owns latency, cost, and incident response. Not the
SOC, not compliance-as-buyer (they are beneficiaries of the audit chain, not the wedge).

Consequences of this choice:

1. **Latency proof outranks feature breadth.** §8.1 is the buying criterion: the next
   load-bearing milestone is P99 validation on a real inference host (TLS + concurrent
   tenants), not more detectors. No new detection layer ships until the current path is
   proven under production-shaped load.
2. **Gateway-first, kernel as upsell.** The gateway must be fully useful without the LSM
   layer loaded (§8.3) — platform teams adopt the gateway in an afternoon; the host plane
   (ank-run scoping, revocation, audit) is the defense-in-depth expansion once trust is
   earned, because it carries the privileged-deployment tax.
3. **Phase 2 order follows platform pain:** (a) pluggable detector interface (bring-your-
   own-model — we do not out-classify Lakera/Mindgard, we host the customer's classifier
   under our budget + audit), then (b) RAG/vector-store poisoning, then (c) SIEM delivery
   beyond JSON export (syslog/webhook) driven by the first design partner's SOC.
4. **What we still refuse:** EDR-style host breadth beyond the model-server scope,
   transformer-grade classifiers as a built product, and compliance-led positioning.
   Those serve different buyers with different budgets.
