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

## Useful commands

There are some scripts in the cmd/debug folder that could prove useful:

- Generating some fake data can be done by using the `populate` command. By default it will generate 1000 posts and 10 users, but this can be configured by passing specific flags.

```
go run ./cmd/debug/populate
```

- Creating a admin account is done via the `createadmin` command. The credentials are passed via command line arguments, like this:

```
go run ./cmd/debug/createadmin.go -email <email> -password <password> -username <username>
```