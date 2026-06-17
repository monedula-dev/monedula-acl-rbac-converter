docker exec broker kafka-acls.sh --bootstrap-server kafka:9092 \
  --add --allow-principal User:bob --operation Read --group billing-consumer
