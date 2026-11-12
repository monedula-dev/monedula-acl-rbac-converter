# monedula-acl-rbac

[![CI](https://github.com/monedula-dev/monedula-acl-rbac-converter/actions/workflows/ci.yml/badge.svg)](https://github.com/monedula-dev/monedula-acl-rbac-converter/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/monedula-dev/monedula-acl-rbac-converter)](https://github.com/monedula-dev/monedula-acl-rbac-converter/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/monedula-dev/monedula-acl-rbac-converter.svg)](https://pkg.go.dev/github.com/monedula-dev/monedula-acl-rbac-converter)
[![License: AGPL v3](https://img.shields.io/badge/license-AGPL%20v3-blue.svg)](LICENSE)

A CLI that converts Apache Kafka ACLs into Confluent RBAC role bindings through a checksummed plan, and verifies effective access before any ACL is deleted.

**Documentation:** [monedula.dev/flock/docs/acl-rbac-converter](https://monedula.dev/flock/docs/acl-rbac-converter/)

- [Install monedula-acl-rbac](https://monedula.dev/flock/docs/acl-rbac-converter/how-to/install/): `go install`, the signed release archives and shell completion
- [Your first ACL to RBAC migration](https://monedula.dev/flock/docs/acl-rbac-converter/tutorials/first-migration/), the full pipeline against a local Confluent Platform, or [Convert ACLs in one command](https://monedula.dev/flock/docs/acl-rbac-converter/tutorials/one-shot-conversion/)
- [Two paths: with or without MDS](https://monedula.dev/flock/docs/acl-rbac-converter/concepts/two-paths/): apply the bindings yourself, or hand them to a CD pipeline
- [How ACLs map to RBAC roles](https://monedula.dev/flock/docs/acl-rbac-converter/concepts/how-acls-map-to-rbac/) and the [Safety guarantees](https://monedula.dev/flock/docs/acl-rbac-converter/concepts/safety-guarantees/) around every change
- [CLI overview](https://monedula.dev/flock/docs/acl-rbac-converter/reference/cli/): every command, flag and exit code
- [Config files](https://monedula.dev/flock/docs/acl-rbac-converter/reference/config-files/): `scopes.yaml`, `rules.yaml`, `principals.yaml` and `vars.yaml`
- [Limitations and API stability](https://monedula.dev/flock/docs/acl-rbac-converter/concepts/limitations/)

## Install

```bash
go install github.com/monedula-dev/monedula-acl-rbac-converter/cmd/monedula-acl-rbac@latest
```

The [install page](https://monedula.dev/flock/docs/acl-rbac-converter/how-to/install/) covers the prebuilt archives for Linux, macOS and Windows, verifying them with cosign, and shell completion.

## Try it

Convert a saved `kafka-acls.sh --list` dump into a script of role-binding commands, without touching any cluster:

```bash
monedula-acl-rbac convert --from text --input acls.txt --scopes scopes.yaml > bindings.sh
```

The full migration runs `extract`, `plan`, `apply`, `verify` and `delete-acls`, each step writing its audit artifacts to a run directory. [Your first ACL to RBAC migration](https://monedula.dev/flock/docs/acl-rbac-converter/tutorials/first-migration/) walks through it.

## Runnable examples

[`examples/`](examples/) holds one end-to-end flow per ACL source, each with a README, a `run.sh` and the expected output committed under `expected/`. [`live-mds-migration/`](examples/live-mds-migration/) runs the whole pipeline against a real MDS in Docker; the file-based examples, such as [`text-dump/`](examples/text-dump/), need only the binary:

```bash
cd examples/text-dump
./run.sh --check   # regenerates out/ and diffs it against expected/
```

[Runnable examples](https://monedula.dev/flock/docs/acl-rbac-converter/reference/examples/) lists them all with what each one needs.

## Building from source

With Go 1.26.11 or newer:

```bash
git clone https://github.com/monedula-dev/monedula-acl-rbac-converter.git
cd monedula-acl-rbac-converter
go build ./cmd/monedula-acl-rbac
go test ./...
```

[CONTRIBUTING.md](CONTRIBUTING.md) lists the lint checks, and [TESTING.md](TESTING.md) the e2e, integration and fuzz suites.

## Contributing and security

Report bugs and request features in [GitHub issues](https://github.com/monedula-dev/monedula-acl-rbac-converter/issues). Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request, and [SECURITY.md](SECURITY.md) before reporting a vulnerability. [CHANGELOG.md](CHANGELOG.md) lists the changes in each release.

## License

monedula-acl-rbac is licensed under the AGPL-3.0; see [LICENSE](LICENSE). Using it to migrate your own clusters does not oblige you to share your code, ACLs or plans: AGPL obligations apply when you distribute it, modified or not, or let others use a modified version over a network. For commercial licensing, [contact us](https://monedula.dev/contact/).

Apache Kafka, Kafka and the Kafka logo are trademarks of The Apache Software Foundation. Confluent is a trademark of Confluent, Inc. monedula-acl-rbac is an independent project that works with Kafka clusters and Confluent Platform; it is not affiliated with, endorsed by or sponsored by the ASF or Confluent.
