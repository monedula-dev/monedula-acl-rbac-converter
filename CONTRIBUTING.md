# Contributing to monedula-acl-rbac

Thanks for considering a contribution. This file describes the bare
minimum so you can land a PR quickly.

## Development setup

- Go 1.26+ (matches `go.mod`).
- A POSIX shell or PowerShell. The Makefile uses `go run` for any
  cross-platform helpers; everything else is `go ...`.

```sh
git clone https://github.com/monedula-dev/monedula-acl-rbac-converter
cd monedula-acl-rbac-converter
go build ./...
go test ./...                                     # unit tests
go test -tags e2e ./tests/e2e/...                 # in-process e2e (no Docker)
go test -tags integration ./tests/integration/... # cp-kafka via testcontainers (Docker required)
```

The same targets are available via `make test`, `make test-e2e`, and
`make test-integration`.

See [`TESTING.md`](TESTING.md) for the test-layer pyramid, the anti-regression
principles (test executed artefacts, contract-test shared files, prove flags
have observable effects, adversarial security tests), the finding→test
regression index, and the coverage policy.

## Code style

- Standard `gofmt` (no `goimports`-specific imports). CI fails on unformatted
  files via golangci-lint's formatter gate, so run `gofmt -w` before pushing.
  (Note: gofmt also normalises doc comments — it rewrites two adjacent
  apostrophes and double back-ticks into typographic quotes; keep such literals
  in indented code blocks, as in `pkg/aclrbac/emit/shell/quote.go`.)
- `make lint` must pass. It runs `go vet ./...` **and** `golangci-lint run ./...`
  — the same checks CI runs, including the gofmt gate. Running only `go vet`
  locally is not enough (a PR can pass that and still fail CI). Install the
  linter with
  `go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2`.
- Tests first when fixing a bug or adding behavior. See
  `pkg/aclrbac/extract/text/text_test.go` for the table-driven style
  used throughout.
- Match the existing structure: the core packages live under
  `pkg/aclrbac`, the CLI surface in `pkg/aclrbac/cli`, and subcommand
  implementations in `pkg/aclrbac/cmds/<name>/`. Note that `pkg/aclrbac/...`
  is **internal-by-convention**, not a supported public API — the only
  stability promise is the CLI (see the "API stability" note in the
  README). Exported symbols may change between releases without a major
  version bump, so refactor freely within that tree.

## Commit style

Short imperative subject lines, optionally with a Conventional Commits
prefix that matches what's already in `git log`:

- `feat(area): ...`
- `fix(area): ...`
- `test(area): ...`
- `docs: ...`
- `ci: ...`
- `chore(deps): ...`

Separate body lines explain the why.

## Pull requests

- Open against `main`.
- Include or update tests for any behavior change.
- For user-facing changes, update `README.md` and add a line under
  `## [Unreleased]` in `CHANGELOG.md`.
- One reviewer approval before merge.

## Releases

Maintainers: see [`RELEASING.md`](RELEASING.md) for the tag-time checklist
(CHANGELOG stamp, version-reference sweep, local gate, dry-run, tag, draft-
release review). The repository is kept in a "prepared but not tagged" state
between releases — `CHANGELOG.md`'s `## [Unreleased]` section becomes the
next version's entry at tag time.

## Reporting bugs

Open a GitHub issue using the template. For security issues, see
`SECURITY.md`.

## Bumping golangci-lint

The linter binary version is pinned in three places — keep them in sync
when bumping (dependabot tracks the action, not the binary, and
pre-commit tracks its own pin):

1. `.github/workflows/ci.yml` — `version:` input on `golangci-lint-action`.
2. `.pre-commit-config.yaml` — `rev:` on the `golangci-lint` repo.
3. (Implicitly) the version a contributor's `golangci-lint` produces locally;
   `go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@vX.Y.Z`
   is the canonical install command.

When a major version of `golangci-lint-action` lands (e.g., v6 → v7 for the
golangci-lint v2 binary line), bump both the action and the binary together.
