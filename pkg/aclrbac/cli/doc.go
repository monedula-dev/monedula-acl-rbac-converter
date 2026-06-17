// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package cli

// Flag-behaviour testing convention (anti-dead-flag rule)
// =======================================================
//
// Every behaviour-affecting flag MUST have a test that asserts the flag
// changes an observable output. A flag with no such test is presumed DEAD
// and may be silently inert — that is exactly how the project shipped
// `--verify-parallelism` (wired to a struct field nothing read) and
// `--accept-unknown-verify` (set by the CLI, never consumed inside
// verify.Run). "The flag exists and the run succeeds" is NOT evidence the
// flag does anything.
//
// A conforming test does both halves of the contrast:
//
//   - WITHOUT the flag (or its default): observe baseline output.
//   - WITH the flag set: observe the output CHANGED in the documented way.
//
// Reference tests that codify this for the two flags that bit us:
//
//   - --accept-unknown-verify:
//     verify.TestVerify_AcceptUnknownDowngradesEffectiveUnknown asserts a
//     row stays EFFECTIVE_UNKNOWN without the flag and becomes EFFECTIVE_OK
//     (with a Detail noting the downgrade) with it. Its B5 sibling
//     verify.TestVerify_ProbeFailureNotMaskedByAcceptUnknown pins the
//     boundary: the flag must NOT downgrade a genuine MDS outage.
//
//   - --verify-parallelism:
//     verify.TestVerify_BindingsExist_RunsInParallel asserts peak in-flight
//     concurrency scales with the flag — parallelism=N reaches N concurrent
//     MDS calls (proving the worker pool is live), and parallelism=1
//     serialises (peak never exceeds 1, proving the flag throttles).
//
// When adding a new behaviour-affecting flag, add the analogous WITH/WITHOUT
// contrast test in the package that owns the behaviour (not just a CLI
// smoke test that the flag parses). See TESTING.md ("Every behavior-affecting
// flag needs a test that the flag changes an observable output").
