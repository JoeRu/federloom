# Docker Image Publishing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish `ghcr.io/joeru/swarmguard:latest` to GitHub Container Registry on every push to `main`, and update all deploy compose files to pull the pre-built image instead of building from source.

**Architecture:** A new `.github/workflows/docker.yml` workflow triggers on `main` push, logs in with `GITHUB_TOKEN`, and uses `docker/build-push-action` to build and push. All four compose files drop their `build:` blocks in favour of `image: ghcr.io/joeru/swarmguard:latest`. The Dockerfile gets a Go version fix (`1.25` → `1.22`) and OCI labels.

**Tech Stack:** GitHub Actions, `docker/login-action@v3`, `docker/build-push-action@v5`, GHCR (`ghcr.io`), Alpine Linux runtime image.

---

## File Map

| File | Action | What changes |
|---|---|---|
| `.github/workflows/docker.yml` | Create | Build-and-push workflow triggered on `main` push |
| `deploy/docker/Dockerfile` | Modify | Fix `golang:1.25` → `golang:1.22`; add OCI labels |
| `deploy/docker/docker-compose.yml` | Modify | Replace `build:` with `image: ghcr.io/joeru/swarmguard:latest` |
| `deploy/mailcow/docker-compose.yml` | Modify | Replace `image: swarmguard:latest` + `build:` with `image: ghcr.io/joeru/swarmguard:latest` |
| `deploy/wordpress/docker-compose.yml` | Modify | Replace `image: swarmguard:latest` + `build:` with `image: ghcr.io/joeru/swarmguard:latest` |
| `deploy/honeypot/docker-compose.yml` | Modify | Replace `image: swarmguard:latest` + `build:` with `image: ghcr.io/joeru/swarmguard:latest` |
| `deploy/mailcow/bootstrap-mailcow.sh` | Modify | Replace `docker build` step with `docker pull ghcr.io/joeru/swarmguard:latest` |
| `deploy/wordpress/bootstrap-wordpress.sh` | Modify | Replace `docker build` step with `docker pull ghcr.io/joeru/swarmguard:latest` |

---

## Task 1: Fix Dockerfile and create GitHub Actions workflow

**Files:**
- Modify: `deploy/docker/Dockerfile`
- Create: `.github/workflows/docker.yml`

- [ ] **Step 1: Fix the Dockerfile**

Replace the full content of `deploy/docker/Dockerfile` with:

```dockerfile
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
```

- [ ] **Step 2: Verify the Go version change**

```bash
grep "FROM golang" deploy/docker/Dockerfile
```

Expected output:
```
FROM golang:1.22 AS build
```

- [ ] **Step 3: Create the GitHub Actions workflow**

Write the following to `.github/workflows/docker.yml`:

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
          tags: ghcr.io/joeru/swarmguard:latest
```

- [ ] **Step 4: Verify the workflow file exists and has the right trigger**

```bash
grep -A3 "^on:" .github/workflows/docker.yml
```

Expected output:
```
on:
  push:
    branches: [main]
```

- [ ] **Step 5: Verify existing CI workflow is untouched**

```bash
cat .github/workflows/ci.yml
```

Expected: the file is unchanged (still has `build-test` and `adversarial` jobs, no docker references).

- [ ] **Step 6: Commit**

```bash
git add deploy/docker/Dockerfile .github/workflows/docker.yml
git commit -m "ci: add GHCR image publish workflow; fix Dockerfile Go version to 1.22"
```

---

## Task 2: Update compose files to use the published image

**Files:**
- Modify: `deploy/docker/docker-compose.yml`
- Modify: `deploy/mailcow/docker-compose.yml`
- Modify: `deploy/wordpress/docker-compose.yml`
- Modify: `deploy/honeypot/docker-compose.yml`

### `deploy/docker/docker-compose.yml`

This file has only a `build:` line (no `image:` line). Replace the `build:` line with `image:`.

- [ ] **Step 1: Update `deploy/docker/docker-compose.yml`**

Replace the full content with:

```yaml
# Standalone deployment (outside Mailcow).
services:
  swarmguard:
    image: ghcr.io/joeru/swarmguard:latest
    container_name: swarmguard
    restart: unless-stopped
    cap_add: [ NET_ADMIN, NET_RAW ]
    network_mode: host
    volumes:
      - ./config.yaml:/etc/swarmguard/config.yaml:ro
      - swarmguard-data:/var/lib/swarmguard
volumes:
  swarmguard-data:
```

### `deploy/mailcow/docker-compose.yml`

This file has `image: swarmguard:latest` (local tag) AND a `build:` block. Replace both with the GHCR image. All other fields are unchanged.

- [ ] **Step 2: Update `deploy/mailcow/docker-compose.yml`**

Replace the full content with:

```yaml
# SwarmGuard sidecar for Mailcow.
#
# network_mode: host matches the cs-firewall-bouncer pattern:
#   - reaches CrowdSec LAPI at 127.0.0.1:8080 without touching the mailcow network
#   - ipset/iptables calls affect the host kernel directly (requires NET_ADMIN)
#
# Before starting:
#   1. Open port 7700 in the NixOS firewall if you want peers to initiate connections here
services:
  swarmguard:
    image: ghcr.io/joeru/swarmguard:latest
    container_name: swarmguard-mailcow
    restart: unless-stopped
    cap_add: [NET_ADMIN, NET_RAW]
    network_mode: host
    volumes:
      - ./config.local.yaml:/etc/swarmguard/config.yaml:ro
      - ./rules.yaml:/etc/swarmguard/rules.yaml:ro
      - swarmguard-data:/var/lib/swarmguard
      - /var/run/docker.sock:/var/run/docker.sock:ro
    command: >
      --config /etc/swarmguard/config.yaml
      --listen /ip4/0.0.0.0/tcp/7700
      --advertise /ip4/135.181.91.151/tcp/7700

volumes:
  swarmguard-data:
```

Note: the comment referencing `bootstrap-mailcow.sh` step 1 ("builds image") is removed since the image is now pre-built.

### `deploy/wordpress/docker-compose.yml`

- [ ] **Step 3: Update `deploy/wordpress/docker-compose.yml`**

Replace the full content with:

```yaml
# SwarmGuard sidecar for WordPress/Traefik stack.
#
# network_mode: host is required so the container can:
#   - reach CrowdSec LAPI at 172.21.0.3:8080 (internal traefik Docker bridge)
#   - apply ipset/iptables rules to the host kernel (requires NET_ADMIN)
#
# The CrowdSec container is NOT exposed on host ports; it lives on the internal
# traefik network (172.21.0.0/16). The host has 172.21.0.1 as the bridge gateway,
# so network_mode: host lets SwarmGuard reach 172.21.0.3:8080 directly.
#
# Before starting:
#   1. Open port 7700 in the NixOS firewall if you want peers to initiate connections here
services:
  swarmguard:
    image: ghcr.io/joeru/swarmguard:latest
    container_name: swarmguard-wordpress
    restart: unless-stopped
    cap_add: [NET_ADMIN, NET_RAW]
    network_mode: host
    volumes:
      - ./config.local.yaml:/etc/swarmguard/config.yaml:ro
      - ./rules.yaml:/etc/swarmguard/rules.yaml:ro
      - swarmguard-data:/var/lib/swarmguard
    command: >
      --config /etc/swarmguard/config.yaml
      --listen /ip4/0.0.0.0/tcp/7700
      --advertise /ip4/65.108.62.108/tcp/7700

volumes:
  swarmguard-data:
```

### `deploy/honeypot/docker-compose.yml`

- [ ] **Step 4: Update `deploy/honeypot/docker-compose.yml`**

Replace the full content with:

```yaml
# Honeypot stack: Cowrie (SSH) + OpenCanary (SMTP/IMAP) + SwarmGuard node.
# Deploy via deploy/honeypot/bootstrap.sh — do not run directly without reading that script.
services:
  cowrie:
    image: cowrie/cowrie:latest
    container_name: cowrie
    restart: unless-stopped
    ports:
      - "22:2222"
    volumes:
      - cowrie-logs:/cowrie/cowrie-git/var/log/cowrie

  opencanary:
    image: thinkst/opencanary:latest
    container_name: opencanary
    restart: unless-stopped
    ports:
      - "25:25"
      - "143:143"
    volumes:
      - opencanary-logs:/var/log/opencanary
      - ./opencanary.json:/etc/opencanaryd/opencanary.conf:ro

  swarmguard:
    image: ghcr.io/joeru/swarmguard:latest
    container_name: swarmguard
    restart: unless-stopped
    cap_add: [NET_ADMIN, NET_RAW]
    ports:
      - "7700:7700"
      - "9101:9101"
      - "9102:9102"
    volumes:
      - ./config.yaml:/etc/swarmguard/config.yaml:ro
      - ./rules.yaml:/etc/swarmguard/rules.yaml:ro
      - cowrie-logs:/var/log/cowrie:ro
      - opencanary-logs:/var/log/opencanary:ro
      - swarmguard-data:/var/lib/swarmguard
    command: >
      --config /etc/swarmguard/config.yaml
      --listen /ip4/0.0.0.0/tcp/7700
      --advertise /ip4/213.199.36.212/tcp/7700
    depends_on:
      - cowrie
      - opencanary

volumes:
  cowrie-logs:
  opencanary-logs:
  swarmguard-data:
```

- [ ] **Step 5: Verify no `build:` blocks remain in any compose file**

```bash
grep -r "build:" deploy/
```

Expected output: (empty — no matches)

- [ ] **Step 6: Verify all four compose files reference the GHCR image**

```bash
grep -r "image:" deploy/*/docker-compose.yml
```

Expected output (order may vary):
```
deploy/docker/docker-compose.yml:    image: ghcr.io/joeru/swarmguard:latest
deploy/mailcow/docker-compose.yml:    image: ghcr.io/joeru/swarmguard:latest
deploy/wordpress/docker-compose.yml:    image: ghcr.io/joeru/swarmguard:latest
deploy/honeypot/docker-compose.yml:    image: cowrie/cowrie:latest
deploy/honeypot/docker-compose.yml:    image: thinkst/opencanary:latest
deploy/honeypot/docker-compose.yml:    image: ghcr.io/joeru/swarmguard:latest
```

- [ ] **Step 7: Run the Go test suite to confirm nothing is broken**

```bash
make test
```

Expected: all packages pass (compose changes have no effect on Go tests).

- [ ] **Step 8: Commit**

```bash
git add deploy/docker/docker-compose.yml \
        deploy/mailcow/docker-compose.yml \
        deploy/wordpress/docker-compose.yml \
        deploy/honeypot/docker-compose.yml
git commit -m "deploy: use ghcr.io/joeru/swarmguard:latest in all compose files"
```

---

## Task 3: Update bootstrap scripts to pull instead of build

**Files:**
- Modify: `deploy/mailcow/bootstrap-mailcow.sh`
- Modify: `deploy/wordpress/bootstrap-wordpress.sh`

Both scripts currently build the image on the remote server (step 3) with `docker build`. Replace this step with `docker pull ghcr.io/joeru/swarmguard:latest`. The rsync in step 2 is still needed for config files, scripts, and rules — only the build step changes.

### `deploy/mailcow/bootstrap-mailcow.sh`

Current step 3 (lines 46-48):
```bash
echo "==> [3/6] Building swarmguard image on server"
sudo_run docker build -t swarmguard:latest \
  -f "$REMOTE_DIR/deploy/docker/Dockerfile" "$REMOTE_DIR" -q
```

- [ ] **Step 1: Replace the build step in `deploy/mailcow/bootstrap-mailcow.sh`**

Replace those three lines with:
```bash
echo "==> [3/6] Pulling swarmguard image"
sudo_run docker pull ghcr.io/joeru/swarmguard:latest
```

- [ ] **Step 2: Verify the change**

```bash
grep -A2 "\[3/6\]" deploy/mailcow/bootstrap-mailcow.sh
```

Expected output:
```
echo "==> [3/6] Pulling swarmguard image"
sudo_run docker pull ghcr.io/joeru/swarmguard:latest
```

### `deploy/wordpress/bootstrap-wordpress.sh`

Current step 3 (lines 49-51):
```bash
echo "==> [3/6] Building swarmguard image on server"
ssh_run docker build -t swarmguard:latest \
  -f "$REMOTE_DIR/deploy/docker/Dockerfile" "$REMOTE_DIR" -q
```

- [ ] **Step 3: Replace the build step in `deploy/wordpress/bootstrap-wordpress.sh`**

Replace those three lines with:
```bash
echo "==> [3/6] Pulling swarmguard image"
ssh_run docker pull ghcr.io/joeru/swarmguard:latest
```

- [ ] **Step 4: Verify the change**

```bash
grep -A2 "\[3/6\]" deploy/wordpress/bootstrap-wordpress.sh
```

Expected output:
```
echo "==> [3/6] Pulling swarmguard image"
ssh_run docker pull ghcr.io/joeru/swarmguard:latest
```

- [ ] **Step 5: Verify no `docker build` references remain in either bootstrap script**

```bash
grep "docker build" deploy/mailcow/bootstrap-mailcow.sh deploy/wordpress/bootstrap-wordpress.sh
```

Expected output: (empty — no matches)

- [ ] **Step 6: Run tests to confirm nothing broken**

```bash
make test
```

Expected: all packages pass.

- [ ] **Step 7: Commit**

```bash
git add deploy/mailcow/bootstrap-mailcow.sh deploy/wordpress/bootstrap-wordpress.sh
git commit -m "deploy: pull swarmguard image from GHCR instead of building on server"
```

---

## Self-Review Notes

**Spec coverage:**
- ✅ `.github/workflows/docker.yml` — Task 1
- ✅ Dockerfile Go version fix (`1.25` → `1.22`) — Task 1
- ✅ Dockerfile OCI labels — Task 1
- ✅ `deploy/docker/docker-compose.yml` (Pattern A) — Task 2
- ✅ `deploy/mailcow/docker-compose.yml` (Pattern B) — Task 2
- ✅ `deploy/wordpress/docker-compose.yml` (Pattern B) — Task 2
- ✅ `deploy/honeypot/docker-compose.yml` (Pattern B) — Task 2

**No placeholders found.**

**Spec coverage:**
- ✅ `.github/workflows/docker.yml` — Task 1
- ✅ Dockerfile Go version fix (`1.25` → `1.22`) — Task 1
- ✅ Dockerfile OCI labels — Task 1
- ✅ `deploy/docker/docker-compose.yml` (Pattern A) — Task 2
- ✅ `deploy/mailcow/docker-compose.yml` (Pattern B) — Task 2
- ✅ `deploy/wordpress/docker-compose.yml` (Pattern B) — Task 2
- ✅ `deploy/honeypot/docker-compose.yml` (Pattern B) — Task 2
- ✅ Bootstrap scripts updated to pull instead of build — Task 3 (added after discovering `docker build` calls in bootstrap scripts not covered by spec)
