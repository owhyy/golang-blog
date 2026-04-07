FROM golang:1.25.4-alpine AS builder

# Required for CGO
RUN apk add --no-cache gcc musl-dev ca-certificates

WORKDIR /app

COPY go.mod ./
COPY . .

RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 \
    go build -a -installsuffix cgo \
    -ldflags "-s -w -extldflags '-static'" \
    -o blog ./cmd/web

RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 \
    go build -a -installsuffix cgo \
    -ldflags "-s -w -extldflags '-static'" \
    -o populate ./cmd/debug/populate.go

RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 \
    go build -a -installsuffix cgo \
    -ldflags "-s -w -extldflags '-static'" \
    -o createadmin ./cmd/debug/createadmin.go

FROM scratch
COPY --from=builder /app/blog /blog
COPY --from=builder /app/populate /populate
COPY --from=builder /app/createadmin /createadmin
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE 8080
ENTRYPOINT ["/blog"]
