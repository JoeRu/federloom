# Build
FROM golang:1.22 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /out/swarmd ./cmd/swarmd \
 && CGO_ENABLED=0 go build -o /out/swarmctl ./cmd/swarmctl

# Runtime — needs iptables/ipset tooling for the enforce backends
FROM alpine:3.20
RUN apk add --no-cache iptables ipset nftables docker-cli
COPY --from=build /out/swarmd /usr/local/bin/swarmd
COPY --from=build /out/swarmctl /usr/local/bin/swarmctl
LABEL org.opencontainers.image.source="https://github.com/JoeRu/swarmguard"
LABEL org.opencontainers.image.description="Federated IP reputation daemon"
ENTRYPOINT ["/usr/local/bin/swarmd"]
