#!/usr/bin/env bash
# The kind of provisioning script teams keep in a repo to seed a cluster's
# ACLs. monedula-acl-rbac extract --from script parses these `kafka-acls --add`
# invocations (substituting --vars) into canonical ACL rows. It never runs them.
#
# $ORDERS_TOPIC is supplied via vars.yaml so the parser does not have to guess.
set -euo pipefail

# svc-orders-consumer: read the orders topic and commit to its consumer group.
kafka-acls --add --allow-principal User:svc-orders-consumer \
  --operation Read --operation Describe --topic "$ORDERS_TOPIC"
kafka-acls --add --allow-principal User:svc-orders-consumer \
  --operation Read --operation Describe --group orders-consumers

# svc-payments-producer: write the payments topic.
kafka-acls --add --allow-principal User:svc-payments-producer \
  --operation Write --operation Describe --topic payments

# svc-analytics: read everything under the events. prefix.
kafka-acls --add --allow-principal User:svc-analytics \
  --operation Read --operation Describe \
  --topic events. --resource-pattern-type prefixed

# svc-orders-owner: full control of the orders topic (All -> ResourceOwner).
kafka-acls --add --allow-principal User:svc-orders-owner \
  --operation All --topic "$ORDERS_TOPIC"

# svc-orders-relay: consumes AND re-publishes the orders topic. Read+Write on
# one resource maps to two roles (DeveloperRead + DeveloperWrite).
kafka-acls --add --allow-principal User:svc-orders-relay \
  --operation Read --operation Write --operation Describe --topic "$ORDERS_TOPIC"

# legacy-importer: a DENY -- has no RBAC equivalent, so the planner rejects it.
kafka-acls --add --deny-principal User:legacy-importer \
  --operation Read --topic pii-events
