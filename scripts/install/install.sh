#!/usr/bin/env bash
# SwarmGuard installer. Seeds the local-only whitelist after explicit operator
# confirmation (spec §6.2). Conservative by design: when in doubt, do NOT add.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

echo "== SwarmGuard install =="
echo "Step 1: detect local truth for the local-only whitelist"
echo

# Capture once so we can print for review AND iterate without re-running the script.
detected=$("$HERE/detect_local_truth.sh")
echo "$detected"
echo

read -r -p "Write the confirmed entries to the local-only whitelist? [y/N] " ans
case "${ans:-N}" in
  y|Y)
    if ! command -v swarmctl >/dev/null 2>&1; then
      echo "error: swarmctl not found in PATH — build and install it first:" >&2
      echo "  make build && cp bin/swarmctl /usr/local/bin/" >&2
      exit 1
    fi
    count=0
    while IFS= read -r line; do
      # Skip blank lines, comment/header lines (start with #), and NOTE: lines.
      [[ -z "$line" || "$line" == \#* || "$line" == NOTE:* ]] && continue
      if swarmctl whitelist add --scope local-only --source install-script "$line" 2>/dev/null; then
        count=$((count + 1))
      else
        printf "  warning: skipped %s (not a valid IP/CIDR)\n" "$line" >&2
      fi
    done <<< "$detected"
    echo "wrote $count entries to local-only whitelist"
    ;;
  *)
    echo "Aborted — nothing written."
    ;;
esac
echo "Next: edit config.yaml (see deploy/examples/) and start the daemon."
