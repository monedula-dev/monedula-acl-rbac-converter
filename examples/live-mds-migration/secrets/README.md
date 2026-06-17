# secrets/ — throwaway local-dev credentials

**None of these are real secrets.** They exist only to stand up an ephemeral,
single-node Confluent stack on your laptop for this example, and are committed on
purpose so the stack runs with no setup. Never reuse them anywhere real.

| File | What it is |
|---|---|
| `keypair.pem` / `public.pem` | A throwaway RSA keypair MDS uses to sign/verify its bearer tokens. Regenerate with `openssl genrsa -traditional -out keypair.pem 2048 && openssl rsa -in keypair.pem -pubout -out public.pem`. |
| `bootstrap.ldif` | Seeds OpenLDAP with the single `mds` admin user MDS authenticates as. |
| `mds.pw` | The `mds` user's password (`mds-secret`), passed to the CLI via `--mds-password-file`. |

The broker's SASL superuser (`kafka` / `kafka-secret`) is defined inline in
`../docker-compose.yml` and `../client.properties`.
