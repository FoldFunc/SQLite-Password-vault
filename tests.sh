curl -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{"login": "testuser", "password": "testpass"}'
curl -X POST http://localhost:8080/login \
-H "Content-Type: application/json" \
-d '{"login":"testuser", "password":"testpass"}' \
-c cookie.txt
curl -X POST http://localhost:8080/makeVaultEntry \
-H "Content-Type: application/json" \
-d '{"title":"My Gmail", "secret":"superSecret123"}' \
-b cookie.txt

