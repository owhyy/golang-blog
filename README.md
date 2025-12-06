# golang-auth
Simple &amp; secure POC authentication page

## Configuration

See `.env.example` for configuration options

## Running

- Locally:

```
go run main.go handlers.go
```

- Dockerfile (recommended):

```
docker build -t go-auth-app .
docker run --rm -p 8080:8080 go-auth-app:latest
```

Accessing localhost:8080 should open the home page.