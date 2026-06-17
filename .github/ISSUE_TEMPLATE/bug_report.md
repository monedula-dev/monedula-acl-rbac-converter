---
name: Bug report
about: Report unexpected behavior
labels: bug
---

## What happened

(describe the unexpected behavior, including any error message)

## Reproduction

The command(s) you ran, and the input that triggered the issue:

```
$ monedula-acl-rbac ...
```

## Expected behavior

(what you expected to happen instead)

## Environment

- Version: `monedula-acl-rbac --version` output
- OS / shell:
- Source: live cluster / kafka-acls.sh dump / CFK / K8s / other

## Run directory (if applicable)

If the bug happened during a real run, please attach a sanitized copy
of the run directory: `acls.json`, `plan.json`, `report.txt`,
`apply.log`, etc. Strip principals / hostnames if needed.

**Do not paste MDS tokens, passwords, or `runtime.env` contents.**
