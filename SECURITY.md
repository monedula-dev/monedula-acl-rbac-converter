# Security Policy

monedula-acl-rbac rewrites Kafka authorization state. Bugs in this tool
can grant or revoke access to data. Please report security issues
privately.

## Reporting a vulnerability

Please use GitHub's **Private Security Advisory** flow:
<https://github.com/monedula-dev/monedula-acl-rbac-converter/security/advisories/new>.

That routes the report to repository maintainers privately and gives us
a structured workspace for the fix and CVE. Do **not** open a public
issue or discussion for vulnerabilities.

Include:

- A description of the issue and its impact.
- Steps to reproduce, ideally with a minimal `acls.json` or shell
  command.
- The version (or commit hash) of monedula-acl-rbac you tested.
- Any proof-of-concept that demonstrates the issue.

We aim to acknowledge reports within 3 business days and ship a fix
within 30 days for high-severity issues.

## Supported versions

Only the latest released version is supported. Security fixes ship as
patch releases under semver (the first tagged release is `1.0.0`, so the
first patch line is `1.0.x`).

## Out of scope

- Issues that require the operator to already hold MDS or Kafka admin
  credentials (those credentials inherently grant the impact in
  question).
- Bugs in dependencies that do not surface in monedula-acl-rbac. Please
  report those to the upstream project; we will pick up the patch
  when it's released.
