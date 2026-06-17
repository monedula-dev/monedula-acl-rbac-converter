#!/bin/bash
set -e
kafka-acls --bootstrap-server localhost:9092 \
  --add --allow-principal User:alice --operation Read --topic orders
kafka-acls --bootstrap-server localhost:9092 \
  --add --allow-principal User:alice --operation Describe --topic orders
