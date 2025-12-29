FROM golang:1.25.4-alpine AS builder

# Required for CGO
RUN apk add --no-cache gcc musl-dev

WORKDIR /app

COPY go.mod ./
COPY . .

RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 \
    go build -a -installsuffix cgo \
    -ldflags "-s -w -extldflags '-static'" \
    -o simple-auth ./cmd/web

FROM scratch
COPY --from=builder /app/simple-auth /simple-auth
EXPOSE 8080
ENTRYPOINT ["/simple-auth"]
