#!/usr/bin/env bash
# SwarmGuard installer (scaffold). Seeds the local-only whitelist after explicit
# operator confirmation, then points at config. Conservative by design (spec §6.2).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

echo "== SwarmGuard install (scaffold) =="
echo "Step 1: detect local truth for the local-only whitelist"
"$HERE/detect_local_truth.sh"

echo
read -r -p "Write the confirmed entries to the local-only whitelist? [y/N] " ans
case "${ans:-N}" in
  y|Y) echo "TODO: persist confirmed entries via 'swarmctl whitelist add --scope local-only'";;
  *)   echo "Aborted — nothing written.";;
esac
echo "Next: edit config.yaml (see deploy/examples/) and start the daemon."
