for topic in orders shipments; do
  kafka-acls --add --allow-principal User:eve --operation Read --topic "$topic"
done
