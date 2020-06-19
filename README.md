# golang-jwt-basic
golang implementation for JWT auth


How to Run
```
go run *.go
```

How to Test
- Generate Token
```
curl -X GET --user amar:amaragya http://localhost:8080/login
```

-Testing Token
```
curl -X GET  --header "Authorization: Bearer YOUR_JWT_TOKEN_HERE" http://localhost:8080/index
```
