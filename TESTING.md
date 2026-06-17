# Testing strategy

This project converts Kafka ACLs into Confluent RBAC. The high-risk surfaces
are *artefacts shared across components* (acls.json, plan.json, verify.json and
the stdout JSON envelopes), *generated scripts/argv that are later executed*,
and *security-sensitive code* (auth, token cache, shell/URL quoting). The bugs
that historically slipped through review were almost all in those three areas,
and they slipped through because the tests checked each side in isolation
against its own *assumed* shape rather than the contract the other side relied
on.

This document describes the layers we test at, the principles that prevent
those bug classes, and an index mapping each past finding to the test that now
guards it.

See also `CONTRIBUTING.md` for how to run the suites.

## 1. Test layers

| Layer | What it covers | How to run | Docker? |
|---|---|---|---|
| **Unit** | Pure functions, in-package (planner, normaliser, quoting, parsers). | `go test ./...` | no |
| **Component-with-seams** | A command driven through an injection seam: `delete-deny-one` via the `ExecKafkaACLs` function seam; MDS clients via an `httptest` fake MDS; the token cache via an isolated `os.UserConfigDir`. | `go test ./...` | no |
| **Real-exec** | The *production* exec path, not a stand-in: `delete-deny-one` re-execs a real `kafka-acls` binary via `MONEDULA_KAFKA_ACLS_BIN`. The test binary doubles as the stub (`TestMain` writes the received argv to a file and exits 0). | `go test ./...` | no |
| **E2E against a real broker + MDS** | The compiled CLI run end-to-end against a real `cp-server` (broker + RBAC/MDS) stood up by `internal/mdstest` — **no in-process fakes**. A complex, real-life ACL set is created on the broker (over a SASL listener as the `kafka` superuser — `ConfluentServerAuthorizer` rejects the Kafka-native ACL APIs for the ANONYMOUS principal), then `extract → plan → apply → verify → delete` runs over the wire (`TestE2E_ComplexPipeline_LiveMDS`, both CP lines). Two pipelines run against one live stack: a concrete-op set (effective-verifiable, asserted row-by-row out of `acls.json`) that also drives `delete-acls` — the generated script is executed **inside the broker container** and the source ACLs are confirmed gone (the untargeted DENY survives) — and a separate `All`-op set covering the **ResourceOwner** mapping via bindings-exist. The concrete set deliberately includes a consumer holding **two `DeveloperRead` bindings** (its topic *and* its consumer group) so the run exercises MDS binding **aggregation** end to end. | `go test -tags e2e ./tests/e2e/...` | **yes** |
| **Integration against real brokers** | The CLI against a real `cp-kafka` broker via testcontainers (live extract + destructive `kafka-acls --remove` round-trips). | `go test -tags integration ./tests/integration/...` | **yes** |
| **Integration against real MDS** | The production `mds.Client` and the full `extract → plan → apply → verify` pipeline driven against a real `cp-server` (RBAC/MDS + OpenLDAP) via testcontainers — proves the MDS wire contract the in-process fakes can only assume. Runs against **CP 7.9 (ZooKeeper) and 8.2 (KRaft)**, and converts **every file-based input format** (json, yaml, csv, text, strimzi, script) from one complex ACL set (`TestRealMDS_RoleBindingLifecycle`, `TestRealMDS_ConvertAllFormats`). RBAC runs under cp-server's built-in 30-day trial. | `go test -tags integration ./tests/integration/...` | **yes** |

Everything except the last three layers (the e2e and the two integration
rows) runs in the **default** `go test ./...` with **no build tags and no
Docker**, so CI verifies it on every push. Those three are Docker-gated and
`t.Skip()` when Docker is unavailable. The
real-exec layer deliberately lives in the default suite (it needs only the
test binary itself), which is what lets it catch executed-behaviour bugs
without a broker.

## 2. Principles that prevent the bug classes we've hit

These are not aspirational — each maps to bugs that shipped. New tests and
reviews should enforce them.

### 2.1 Test the executed artifact, not just its generated text

A generated script or argv can *read* correct and still *do* the wrong thing.
A `PREFIXED` DENY ACL whose argv omitted `--resource-pattern-type` looked fine
in a golden file but no-op'd when `kafka-acls` ran it; `delete-deny-one` built
a plausible MDS URL but called it unauthenticated. Guard executed behaviour:
re-exec the argv (real-exec layer) or round-trip the script through the thing
that consumes it. See `delete/deny/one_realexec_test.go`.

### 2.2 Contract-test every on-disk artefact shared by a producer and a consumer

For every file (or stdout envelope) where one component writes and another
reads, assert the **shape**, the **`schema_version`**, and any **cross-file
binding** at a seam that imports *both* sides. `verify.json` shipped as a bare
`[]Result` while a consumer expected `{results,counts}`; `schema_version` was
integer `1` in some artefacts and string `"1"` in others; the `plan_sha256`
binding between `verify.json` and `plan.json` could have used incompatible hash
formats and silently never matched. See `tests/contract/contract_test.go` and
the published JSON Schemas in `schemas/` (validated by `pkg/aclrbac/schema`).

### 2.3 Every behavior-affecting flag needs a test that the flag changes an observable output

A flag wired to a struct field that nothing reads is *dead* and a passing
"the run succeeds" test does not prove otherwise. `--verify-parallelism` was
inert; `--accept-unknown-verify` was accepted but never consulted. A
conforming test does both halves of the contrast: baseline **without** the
flag, changed output **with** it. A flag without such a test is presumed dead.
This convention is codified in `pkg/aclrbac/cli/doc.go`.

### 2.4 Security-sensitive code gets adversarial tests, not just happy-path

Auth, the token cache, and shell/URL quoting get hostile inputs and the full
resolution matrix, not one green-path case. The shell-quoting injection bug and
the token-cache OS-user/MDS-user key split both lived in code that had
happy-path coverage. See `emit/shell/quote_test.go` (injection payloads),
`mds/token_test.go` + `mds/token_matrix_test.go` (resolution matrix), and
`delete/deny/deny_test.go` (auth-token mismatch via constant-time compare).

### 2.5 Test the spec's intent and the logic's boundaries — not the implementation's mental model

This is the subtlest class, and the one that bit hardest: a semantic bug where
**the test and the code shared the same wrong assumption.** The DENY-removal
safety analysis asked "does an Allow *cover* the DENY's name" when the correct
question is "do the two resource *sets intersect*". A LITERAL Allow for
`secret-prod` sitting INSIDE a PREFIXED DENY `secret-` makes removal grant
access — but both the planner and the live re-check missed it, and the existing
tests (`TestDeny_SafeToRemove`, `TestDeny_WouldGrantAccess_PrefixedCovers`) only
exercised the cases where the flawed logic happened to be right. Coverage was
high (plan 82%, mds 77%); the oracle was wrong.

Guards against this class:

- **Derive cases from the spec / the domain, not from the code.** For a
  set-membership predicate, enumerate the LITERAL×PREFIXED matrix in both
  directions, including "inside", "outside", "equal", "nested", and wildcard —
  see `types/pattern_overlap_test.go`.
- **Assert invariants, not just examples.** `PatternsOverlap` is tested for
  *symmetry* (order independence), which no single example would reveal.
- **When two code paths must agree on a rule, test the rule once and route both
  through it.** The overlap predicate lives in `types` and is used by both the
  planner and the MDS re-check, so they cannot drift.
- **A high coverage number with a wrong oracle hides semantic bugs.** Coverage
  measures lines executed, not whether the assertion encodes the right answer.

## 3. Regression index (past finding → guarding test)

Two review streams produced findings: the Codex P0–P3 envelope/flag rounds and
the 21-item review (B1–B21). Each row lists the test that now guards it, or
states honestly that the guard is reactive / integration-only.

### Codex envelope & flag rounds

| Finding | Guard test | File |
|---|---|---|
| `status` rejects bare-array `verify.json` | `TestRun_VerifyCounts_BareArrayUnreadable` | `cmds/status/status_test.go` |
| `verify.json` envelope `{results,counts}` not bare array | `TestReadVerify_BareArrayRejected`, `TestReadVerify_Envelope` | `cli/read_verify_test.go` |
| `schema_version` unified as string `"1"` everywhere | `TestSchemaVersion_IsStringOneAcrossAllEmitters` | `tests/contract/contract_test.go` |
| `diff --format json` envelope | `TestValidate*` + diff package tests | `cmds/diff/diff_test.go` |
| `mds list-bindings` `{schema_version,bindings}` envelope | `TestRun_JSONFormat_HasSchemaVersionEnvelope`, `TestRun_YAMLFormat_HasSchemaVersionEnvelope` | `cmds/listbindings/listbindings_test.go` |
| `status.v1.json` / `report.v1.json` schema validation | `TestValidateStatusReport_Valid`, `TestValidateReportOutput_Valid` | `schema/validate_test.go` |
| lock-free `delete-deny-one` | `TestOne_*` (run without a run-dir lock) | `delete/deny/one_test.go` |

### Codex DENY-safety round

| Finding | Guard test | File |
|---|---|---|
| PREFIXED DENY removal grants access via a LITERAL/narrower-prefix Allow inside the denied prefix (planner) | `TestDeny_WouldGrantAccess_LiteralInsidePrefixedDeny`, `TestDeny_WouldGrantAccess_NarrowerPrefixInsidePrefixedDeny` | `plan/deny_test.go` |
| same flaw in the live re-check (delete-deny-one) | `TestOne_PrefixedDenyNotRemovedWhenLiteralGrantInside` | `delete/deny/one_overlap_test.go` |
| overlap predicate correctness + symmetry | `TestPatternsOverlap` | `types/pattern_overlap_test.go` |
| `delete-deny-one` enforces deny_analysis == SAFE_TO_REMOVE (spec §4.4) | `TestOne_RefusesWhenDenyAnalysisNotSafe` | `delete/deny/one_overlap_test.go` |
| generated script checks runtime.env mode 0600 (spec §4.4) | `TestGenerate_RoutesThroughDeleteDenyOne` (mode-check assertion) | `delete/deny/deny_test.go` |
| generated script exports `RUNTIME_AUTH_TOKEN` to the child | `TestGenerate_RoutesThroughDeleteDenyOne` (export ordering assertion) | `delete/deny/deny_test.go` |

### Codex review round (P1–P3, post-DENY-safety)

| Finding | Guard test | File |
|---|---|---|
| P1: generated-script `plan.sha256` guard must be **fail-closed** (refuse when unhashable, not warn-and-continue) with a single `MONEDULA_SKIP_PLAN_HASH_CHECK=1` override | `TestHeader_EmitsRuntimePlanSHA256Guard` (emitted structure incl. fail-closed wording absent), `TestHeader_RuntimeGuard_Executes` (real bash: mismatch→5, unhashable→5, override→0) | `delete/common/common_test.go` |
| P2: bare `*` wildcard principal slipped past the planner's `:*`-only check and could be classified `SAFE_TO_REMOVE` | `TestIsWildcardPrincipal`, `TestDeny_BareWildcardPrincipalUnknown` (planner → UNKNOWN) | `types/principal_test.go`, `plan/deny_test.go` |
| P2: **generator** path refuses wildcard DENYs even if `plan.json` claims `SAFE_TO_REMOVE` (defence in depth; shared `types.IsWildcardPrincipal`) | `TestGenerate_WildcardDenyRefused` (`User:*` and bare `*`, fixture lies SAFE_TO_REMOVE) | `delete/deny/deny_test.go` |
| P1 (follow-up): the **hidden but still invocable** `delete-deny-one` also refuses wildcard DENYs — before the deny_analysis gate, MDS lookup, or `kafka-acls` exec — so a hand-edited/revalidated plan can't drive a wildcard removal through `RunOne` | `TestOne_RefusesWildcardPrincipalEvenWhenPlanSaysSafe` (`User:*` and bare `*`, plan lies SAFE_TO_REMOVE, asserts no exec) | `delete/deny/one_overlap_test.go` |
| P3: duplicate `--revalidate` trust-boundary block in README | — (doc-only; merged into one block) | `README.md` |
| P2 (follow-up): spec §4.4 requires the target acl-id to be in `plan.json::rejected[]` **and** SAFE_TO_REMOVE; code only checked deny_analysis. Now both `delete-deny-one` (RunOne) and the generator (`pickEligibleDeny`) re-check `rejected[]` membership — so a hand-edit fabricating a SAFE_TO_REMOVE entry for a non-rejected acl-id is refused | `TestOne_RefusesWhenNotInRejected` (refuses before exec) | `delete/deny/one_overlap_test.go` |

### 21-item review (B1–B21)

| # | Finding | Guard test | File | Notes |
|---|---|---|---|---|
| B1 | `PREFIXED` DENY argv must carry `--resource-pattern-type` | `TestOne_PrefixedDenyEmitsPatternType`, `TestOne_RealExecPath_PrefixedDenyAndAuth` | `delete/deny/one_test.go`, `delete/deny/one_realexec_test.go` | real-exec proves it on the production path |
| B2 | `delete-acls` runtime-credential validator parity | `TestGenerate_RejectsMissingBootstrapServer` | `delete/acls/acls_test.go` | + golden script `TestGoldenDeleteACLsScript` |
| B3 | `--verify-parallelism` actually parallelises (and serialises) | `TestVerify_BindingsExist_RunsInParallel`, `TestVerify_BindingsExist_Parallelism1Serializes` | `verify/verify_test.go` | both directions |
| B4 | `plan_sha256` stamped into `verify.json` | `TestValidateVerifySummary_RejectsMissingPlanSHA256`, `TestPlanSHA256_VerifyAndDeleteAgree` | `schema/validate_test.go`, `tests/contract/contract_test.go` | contract test pins producer↔consumer hash agreement |
| B5 | `verifyEffective` propagates probe failure (not masked by accept-unknown) | `TestVerify_ProbeFailureNotMaskedByAcceptUnknown` | `verify/verify_test.go` | |
| B6+B7 | atomic writes for run-dir artefacts | `TestWriteAtomic_NoTempLeftBehind`, `TestWriteAtomic_ConcurrentReadsNeverPartial` | `rundir/atomic_test.go` | |
| B8 | eligibility dedupe — non-acceptable status wins | `TestEligible_DuplicateRowsNonAcceptableWins` | `delete/common/common_test.go` | |
| B9 | trim whitespace in delete-deny-acls validator | `TestGenerate_RejectsWhitespaceOnlyMDSURL` | `delete/deny/deny_test.go` | |
| B10 | `shell.Quote(envPath)` in delete-deny script | `TestQuote_Adversarial` + `TestGenerate_RoutesThroughDeleteDenyOne` | `emit/shell/quote_test.go`, `delete/deny/deny_test.go` | quoting invariant + script-content assertion |
| B11 | verify-summary schema includes bindings-exist counts | `TestValidateVerifySummary_Valid` | `schema/validate_test.go` | |
| B12 | `DelegationToken` case in delete-deny argv | `TestOne_DelegationTokenDeny` | `delete/deny/one_test.go` | |
| B13 | `delete-*.sh` runtime-verifies `plan.sha256` | `TestHeader_EmitsRuntimePlanSHA256Guard`, `TestHeader_NoGuardWithoutPlanSHA256`, `TestHeader_RuntimeGuard_Executes` | `delete/common/common_test.go` | the last test runs the emitted guard through real `bash` (Linux-gated): pass / mismatch→5 / unhashable→5 / override→0 |
| B14 | MDS Transport `HTTPS_PROXY` + idle pool | — | — | **guarded reactively only** — `client.go` sets `Proxy: http.ProxyFromEnvironment` and idle-pool limits, but there is no unit test asserting the transport honours the proxy. Candidate for the integration suite. |
| B15 | `backoffDelay` guard against tiny `RetryBase` | `TestRetry_TinyRetryBase_NoPanic` | `mds/retry_test.go` | |
| B16 | `cachePath` `user.Current` env fallback | `TestCachePath_UserCurrentFailsFallsBackToEnv`, `TestCachePath_UserCurrentFailsNoEnvErrors` | `mds/token_cachepath_internal_test.go` | |
| B17 | exit-code test no longer `t.Skip` | `TestExitCodeValues` | `types/exitcode_test.go` | |
| B18 | document `BindingID` Role-lowercase quirk | `TestBindingID_DeterministicAndPrefixed` | `plan/binding_id_test.go` | doc + determinism guard |
| B19 | constant-time auth-token compare (delete-deny-one) | `TestOne_TokenMismatchRefused` | `delete/deny/deny_test.go` | exercises the `subtle.ConstantTimeCompare` reject path |
| B20 | document `--revalidate` trust boundary | `TestRevalidate_RejectsInvalidActionValue` | `plan/revalidate_test.go` | doc + input-validation guard |
| B21 | delete stray `.exe` at repo root | — | — | one-time repo hygiene; no recurring guard needed (`.gitignore` covers `*.exe`) |

### Live-MDS e2e findings

| Finding | Guard test | File |
|---|---|---|
| `verify --mode bindings-exist` reported a planned binding MISSING when real MDS had aggregated it. MDS returns one binding per `(principal, role, scope)` whose `resourcePatterns` is the **union** of every grant, while the planner emits one binding per source ACL — so a principal reading a topic AND its consumer group (both `DeveloperRead`) verified as two-missing even though both patterns were installed. The matcher now uses **containment** (planned patterns ⊆ existing), not exact set-equality. | `TestVerify_BindingsExist_AggregatedBinding` (containment ⇒ EXISTS) + `TestVerify_BindingsExist_ResourcePatternsMustMatch` (unrelated pattern still MISSING) | `verify/bindings_exist.go`, `verify/verify_test.go` |
| `extract --from live` describe filter must set `ResourcePatternType(ANY)`: Confluent's `DescribeAclsRequest.normalizeAndValidate` rejects an UNKNOWN(0) pattern-type filter and hard-closes the connection (vanilla Kafka tolerates it). Production `buildFilters` already sets it; the e2e readiness probe is now held to the same rule. | `TestE2E_ComplexPipeline_LiveMDS` (extract step) | `extract/live/filter.go`, `tests/e2e/complex_pipeline_test.go` |
| The `All` Cluster → SystemAdmin default mapping is **not** exercised live: applying a SystemAdmin binding at the `kafka-cluster` scope returns MDS `400 "No role SystemAdmin at scope …"` on the cp-server trial — cluster-admin roles live at a higher registry scope there. The mapping is unit-tested in the planner; the live All-op coverage is scoped to the ResourceOwner mappings (All Topic / All Group). | `TestE2E_ComplexPipeline_LiveMDS` (all-op pipeline) + planner rule tests | `config/defaults.yaml`, `tests/e2e/complex_pipeline_test.go` |

### Findings that are integration-only or reactive (for the cp-kafka work)

- **B14 (transport proxy/idle pool):** no default-suite guard. The proxy/pool
  behaviour is a `net/http.Transport` configuration; asserting it end-to-end
  needs a real proxy or broker. Add to `tests/integration`.
- **B13 runtime execution:** the guard's emitted text is pinned in the default
  suite, and `TestHeader_RuntimeGuard_Executes` now runs that text through real
  `bash` (Linux-gated) to prove the fail-closed behaviour (pass / mismatch→5 /
  unhashable→5 / `MONEDULA_SKIP_PLAN_HASH_CHECK=1` override→0). Running the guard
  *against a real broker* in-container is still exercised in `tests/integration`
  (`delete_acls_roundtrip_test.go`), where it runs with the override set because
  `plan.json` is intentionally not copied into the container.
- **B21:** repo hygiene, not a behaviour; no test.
- **B18 / B20:** primarily documentation; the listed tests guard the adjacent
  determinism / input-validation behaviour, not the prose.

## 4. Coverage policy

- **CI floor:** the global statement coverage floor is **70%**, enforced on
  Linux in `.github/workflows/ci.yml`. A PR that drops below it fails.
- **Per-package expectation:** security-sensitive packages should sit well
  above the floor. As of the targeted-coverage pass: `emit/shell` 100%,
  `cmds/listbindings` 100%, `cmds/authlogin` 80%, `mds` ~78%. New code in
  `mds`, `cmds/authlogin`, `emit/shell`, and the `delete/*` script generators
  should not regress these.
- **Don't pad the number.** Every test must assert real behaviour. A test that
  raises coverage without an assertion that would fail on a regression is worse
  than no test, because it implies a guard that isn't there.
