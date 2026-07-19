# Shared helpers for example smoke tests. Source from an example's smoke.sh:
#   . "$(git rev-parse --show-toplevel)/test/examples/lib.sh"

# wait_for_score <base-url> <ip> [timeout-seconds]
# Polls GET <base-url>/api/v1/score/<ip> until HTTP 200 (the IP has a
# reputation record — proves detector → ingest → reputation → store → API).
wait_for_score() {
    local base="$1" ip="$2" timeout="${3:-120}"
    local deadline=$(( $(date +%s) + timeout ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        local code
        code=$(curl -s -o /dev/null -w '%{http_code}' "$base/api/v1/score/$ip" || true)
        if [ "$code" = "200" ]; then
            echo "PASS: score record present for $ip"
            return 0
        fi
        sleep 3
    done
    echo "FAIL: no score record for $ip after ${timeout}s"
    return 1
}

# retry <attempts> <sleep-seconds> <command...>
# Retries a command (e.g. cscli inside a container that is still booting).
retry() {
    local attempts="$1" pause="$2"; shift 2
    local i
    for i in $(seq 1 "$attempts"); do
        if "$@"; then return 0; fi
        sleep "$pause"
    done
    echo "FAIL: command did not succeed after $attempts attempts: $*"
    return 1
}
