# golang-blog

Simple blog application featuring user auth and blog post CRUD

## Configuration

See `.env.example` for configuration options

## Running

- Locally:

```
go run ./cmd/web
```

- Dockerfile (recommended):

```
docker build -t go-blog-app .
docker run --env-file .env --rm -p 8080:8080 go-blog-app:latest
```

Accessing localhost:8080 should open the home page.