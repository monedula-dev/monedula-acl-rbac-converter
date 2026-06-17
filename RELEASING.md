# Releasing

This document is the checklist a maintainer follows to cut a tagged release.
It exists because the repository is deliberately kept in a "prepared but not
tagged" state: `CHANGELOG.md` carries an `## [Unreleased]` section that
becomes the next version's entry at tag time, and the release workflow is
gated on a green preflight (lint + test on both Linux and Windows) before
goreleaser signs anything. The steps below are the manual pieces between
"main is green" and "v1.0.0 published".

## Pre-tag checklist

Before tagging, on a clean working tree of `main`:

1. **Pick the version.** Semver. The first tagged release is `1.0.0`;
   subsequent releases follow `MAJOR.MINOR.PATCH`.
2. **Stamp the CHANGELOG.** In `CHANGELOG.md`, rename the existing
   `## [Unreleased]` heading to `## [X.Y.Z] - YYYY-MM-DD` (the date the
   release will publish) and add a fresh empty `## [Unreleased]` section
   above it for future changes.
3. **Sweep version-references.** Search the tree for the previous version
   string and the new one to catch any forgotten doc updates:
   ```sh
   grep -rn 'v[0-9]\+\.[0-9]\+\.[0-9]\+' README.md QUICKSTART.md SECURITY.md \
        CONTRIBUTING.md CHANGELOG.md
   ```
   The README install snippet (`VERSION=...`), the CHANGELOG headings, the
   verification example archive (`monedula-acl-rbac_<ver>_<os>_<arch>...`),
   and the cosign certificate-identity regex should all agree.
4. **Run the local gate.**
   ```sh
   make lint
   go test -race -count=1 ./...
   go test -race -count=1 -tags e2e ./tests/e2e/...
   ```
   These mirror what the release workflow's preflight will run on Linux and
   Windows. If you have Docker available, also run the integration suite:
   `go test -tags integration -count=1 ./tests/integration/...`.
5. **Dry-run goreleaser.** Optional but recommended. Goreleaser no longer
   regenerates schemas / tidies modules in its `before:` hooks (the release
   preflight verifies the tree is already clean), so ensure your local tree
   matches first:
   ```sh
   make sync-schemas && go mod tidy
   git status   # must show no changes
   goreleaser release --snapshot --clean
   ```
6. **Commit the release prep.** Typical message:
   `chore(release): prepare X.Y.Z`. Push to `main` and wait for CI to go
   green on both Linux and Windows.

## Tagging

Create an annotated tag and push it:

```sh
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin vX.Y.Z
```

The `v` prefix is required (the release workflow triggers on `v*`).

The push triggers `.github/workflows/release.yml`, which:

1. Runs the **preflight** job on `ubuntu-latest` and `windows-latest` in
   parallel — the same checks ci.yml runs on every PR
   (schemas dirty-check, `go mod tidy -diff`, lint on Linux, vet, race tests,
   e2e tests, build). The build does **not** run unless both shards pass.
2. Runs the **goreleaser** job on `ubuntu-latest`, which builds for
   Linux/macOS/Windows (amd64 + arm64), produces SBOMs (Syft), signs
   `checksums.txt` keyless via cosign (GitHub OIDC), and creates a
   **draft** GitHub release.

If the preflight fails on either OS, the tag stays but the release isn't
published. Fix forward (delete the tag, push a fix to `main`, re-tag with the
same version), or bump the patch.

## Post-tag: review and publish the draft

Goreleaser is configured with `draft: true`, so the release is created in
the GitHub UI as a draft. Before publishing:

1. Open the draft release on the GitHub releases page.
2. Confirm the artifact list contains the expected archives (`*.tar.gz` for
   Linux/macOS, `*.zip` for Windows), `checksums.txt`, `checksums.txt.sig`,
   `checksums.txt.pem`, and per-archive `*.sbom.json`.
3. The release body's auto-generated changelog is GitHub's "What's Changed"
   list since the previous tag; for the very first release that will be
   thin. Optionally paste the new `## [X.Y.Z]` section from `CHANGELOG.md`
   into the release body.
4. **Publish** the release.

The README's "Verifying a release" section is what users will follow
afterwards. Sanity-check that the cosign verification example still resolves
on the published artifacts before announcing the release.

## Hotfix / patch release

For a security or critical-bug patch on top of `vX.Y.0`:

1. Branch from the tag: `git checkout -b hotfix-X.Y.Z vX.Y.0`.
2. Cherry-pick or write the fix; add a test.
3. Rerun the pre-tag checklist with version `X.Y.Z`.
4. Tag and push as above; the release workflow handles the rest.
5. Forward-port the fix to `main` if it isn't already there.

## Rolling back

A draft release can be deleted from the GitHub UI without trace; the tag can
be deleted with `git push origin :refs/tags/vX.Y.Z`. A **published** release
should not be deleted — issue a `X.Y.(Z+1)` superseding it and announce the
withdrawal.
