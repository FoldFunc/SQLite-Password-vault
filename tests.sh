curl -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{"login": "admin", "password": "1234"}'
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"login": "admin", "password": "1234"}'

