kafka-acls --add --allow-principal User:carol --producer --topic transactions \
  --transactional-id tx-carol-001
kafka-acls --add --allow-principal User:carol --consumer --topic transactions \
  --group carol-grp
