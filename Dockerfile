FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o goscep main.go

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/goscep .
# SPIFFE socket location available to the container
ENV SPIFFE_ENDPOINT_SOCKET=unix:///tmp/spire-agent/public/api.sock
# declare the mount point so users can bind-mount the host socket directory
VOLUME ["/tmp/spire-agent/public/"]
EXPOSE 8080
EXPOSE 8443
ENTRYPOINT ["./goscep"]
CMD []