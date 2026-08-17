FROM golang:1.24-alpine AS builder

WORKDIR /src
COPY . .

WORKDIR /src/cmd/caddy
RUN go mod init caddy-build
RUN go mod edit -replace github.com/eugenioenko/autentico/caddy-plugin=../../
RUN go get github.com/caddyserver/caddy/v2@latest
RUN go get github.com/eugenioenko/autentico/caddy-plugin
RUN CGO_ENABLED=0 go build -o /caddy

FROM alpine:latest

RUN apk add --no-cache ca-certificates mailcap
COPY --from=builder /caddy /usr/bin/caddy

EXPOSE 80 443

CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile"]
