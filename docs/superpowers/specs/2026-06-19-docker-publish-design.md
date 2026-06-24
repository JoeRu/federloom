# Docker Image Publishing Design

**Feature:** GitHub Actions workflow to build and publish FederLoom Docker images to GHCR  
**Date:** 2026-06-19  
**Status:** Approved

---

## Problem

Operators who want to run FederLoom currently have to build from source (`docker build` or `docker compose up --build`). This creates friction for new operators and makes deployments slower. Pre-built images on a public registry let operators start with a single `docker compose up`.

## Goal

- Publish `ghcr.io/joeru/federloom:latest` on every push to `main`
- Update all deploy compose files to pull the pre-built image instead of building from source
- Fix the Dockerfile's Go version to match CI (`1.22`)
- Add OCI image labels for discoverability

No versioned tags, no multi-arch, no Docker Hub mirror — deliberately minimal scope.

---

## Workflow

**File:** `.github/workflows/docker.yml`

Triggers on push to `main`. Uses `GITHUB_TOKEN` (auto-provided, no secrets to configure). Requires `packages: write` permission.

```yaml
name: docker
on:
  push:
    branches: [main]

jobs:
  build-push:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
    steps:
      - uses: actions/checkout@v4
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - uses: docker/build-push-action@v5
        with:
          context: .
          file: deploy/docker/Dockerfile
          push: true
          tags: ghcr.io/joeru/federloom:latest
```

Build context is the repo root (`.`), matching the existing compose `context: ../..` behaviour.

---

## Dockerfile Changes

**File:** `deploy/docker/Dockerfile`

Two changes:

1. Fix Go version: `golang:1.25` → `golang:1.22` (matches `ci.yml` and `go.mod`)
2. Add OCI labels to the runtime stage:

```dockerfile
LABEL org.opencontainers.image.source="https://github.com/JoeRu/federloom"
LABEL org.opencontainers.image.description="Federated IP reputation daemon"
```

Full updated Dockerfile:

```dockerfile
# Build
FROM golang:1.22 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /out/federloomd ./cmd/federloomd \
 && CGO_ENABLED=0 go build -o /out/federloomctl ./cmd/federloomctl

# Runtime — needs iptables/ipset tooling for the enforce backends
FROM alpine:3.20
RUN apk add --no-cache iptables ipset nftables docker-cli
COPY --from=build /out/federloomd /usr/local/bin/federloomd
COPY --from=build /out/federloomctl /usr/local/bin/federloomctl
LABEL org.opencontainers.image.source="https://github.com/JoeRu/federloom"
LABEL org.opencontainers.image.description="Federated IP reputation daemon"
ENTRYPOINT ["/usr/local/bin/federloomd"]
```

---

## Compose File Updates

Four compose files are updated to pull from GHCR instead of building from source.

**Pattern A** (`deploy/docker/docker-compose.yml`): has only `build:`, no `image:` line. Replace `build:` with `image:`:

```yaml
# Before
services:
  federloom:
    build: { context: ../.., dockerfile: deploy/docker/Dockerfile }

# After
services:
  federloom:
    image: ghcr.io/joeru/federloom:latest
```

**Pattern B** (`deploy/mailcow`, `deploy/wordpress`, `deploy/honeypot`): have both `image: federloom:latest` (local tag) and `build:` (Docker's build-and-tag pattern). Replace both with the GHCR image:

```yaml
# Before
services:
  federloom:
    image: federloom:latest
    build:
      context: ../..
      dockerfile: deploy/docker/Dockerfile

# After
services:
  federloom:
    image: ghcr.io/joeru/federloom:latest
```

**Files affected:**
- `deploy/docker/docker-compose.yml` (Pattern A)
- `deploy/mailcow/docker-compose.yml` (Pattern B)
- `deploy/wordpress/docker-compose.yml` (Pattern B)
- `deploy/honeypot/docker-compose.yml` (Pattern B)

All other fields (`restart`, `cap_add`, `network_mode`, `volumes`, etc.) are unchanged.

Operators who want to build locally can still run `docker build -f deploy/docker/Dockerfile .` — the Dockerfile remains in the repo.

---

## File Map

| File | Action |
|---|---|
| `.github/workflows/docker.yml` | Create — build-and-push workflow |
| `deploy/docker/Dockerfile` | Modify — fix Go version, add OCI labels |
| `deploy/docker/docker-compose.yml` | Modify — `build:` → `image:` |
| `deploy/mailcow/docker-compose.yml` | Modify — `build:` → `image:` |
| `deploy/wordpress/docker-compose.yml` | Modify — `build:` → `image:` |
| `deploy/honeypot/docker-compose.yml` | Modify — `build:` → `image:` |

---

## Out of Scope

- Versioned tags (`v1.2.3`) — no release tagging process yet
- Multi-arch builds (arm64) — amd64-only for now
- Docker Hub mirror
- Image scanning / SBOM
- Pushing on PR (only `main` pushes publish)
