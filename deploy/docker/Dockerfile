# Build
FROM golang:1.25 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /out/federloomd ./cmd/federloomd \
 && CGO_ENABLED=0 go build -o /out/federloomctl ./cmd/federloomctl

# Runtime — needs iptables/ipset tooling for the enforce backends
FROM alpine:3.20
LABEL org.opencontainers.image.source="https://github.com/JoeRu/federloom"
LABEL org.opencontainers.image.description="Federated IP reputation daemon"
# docker-cli: required by the fail2ban ingest adapter (docker exec fail2ban-client banned)
RUN apk add --no-cache iptables ipset nftables docker-cli
COPY --from=build /out/federloomd /usr/local/bin/federloomd
COPY --from=build /out/federloomctl /usr/local/bin/federloomctl
ENTRYPOINT ["/usr/local/bin/federloomd"]
