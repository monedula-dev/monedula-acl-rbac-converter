#!/usr/bin/env bash
# Create the "before" state: the source Kafka ACLs a real platform would already
# have. Runs kafka-acls INSIDE the broker container, as the `kafka` superuser
# over the SASL CLIENT listener. Invoked by run.sh once the stack is healthy.
#
# This is the legacy ACL world we are about to migrate to RBAC:
#   svc-orders-consumer   Read+Describe topic orders, Read+Describe group orders-consumers
#   svc-payments-producer Write+Describe topic payments
#   svc-analytics         Read+Describe topic events.*  (PREFIXED)
#   svc-fulfillment       Read+Describe topic shipments
#   svc-orders-relay      Read+Write+Describe topic orders  (read-write -> two roles)
#   legacy-importer       DENY Read topic pii-events    (no RBAC equivalent)
set -euo pipefail

exec docker compose exec -T kafka bash -s <<'SEED'
set -euo pipefail
cat > /tmp/admin.properties <<PROPS
security.protocol=SASL_PLAINTEXT
sasl.mechanism=PLAIN
sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required username="kafka" password="kafka-secret";
PROPS
ACL="kafka-acls --bootstrap-server kafka:9094 --command-config /tmp/admin.properties --add"

$ACL --allow-principal User:svc-orders-consumer   --operation Read --operation Describe --topic orders
$ACL --allow-principal User:svc-orders-consumer   --operation Read --operation Describe --group orders-consumers
$ACL --allow-principal User:svc-payments-producer --operation Write --operation Describe --topic payments
$ACL --allow-principal User:svc-analytics         --operation Read --operation Describe --topic events. --resource-pattern-type prefixed
$ACL --allow-principal User:svc-fulfillment       --operation Read --operation Describe --topic shipments
$ACL --allow-principal User:svc-orders-relay      --operation Read --operation Write --operation Describe --topic orders
$ACL --deny-principal  User:legacy-importer       --operation Read --topic pii-events

echo "--- source ACLs now on the broker ---"
kafka-acls --bootstrap-server kafka:9094 --command-config /tmp/admin.properties --list
SEED
