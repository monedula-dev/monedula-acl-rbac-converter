## Summary

(1-3 bullets describing what this PR does)

## Test plan

- [ ] `make lint` (runs `go vet` **and** `golangci-lint run ./...` — matches CI,
      including the gofmt formatter gate)
- [ ] `go test -race -count=1 ./...` (CI runs with `-race`; race-only failures
      are silent under plain `go test`)
- [ ] `go test -race -count=1 -tags e2e ./tests/e2e/...`
- [ ] (any manual verification specific to this change)

## Related issues

Closes #
