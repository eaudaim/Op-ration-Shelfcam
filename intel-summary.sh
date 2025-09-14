#!/bin/bash
# Generate human readable report from Phase 1 intel JSON

set -u
set -o pipefail

ERROR_LOG="error.log"
log_error(){ echo "[$(date '+%H:%M:%S')] $1" >> "$ERROR_LOG"; }

if [[ $# -ne 1 ]]; then
  log_error "usage: intel-summary <dir>"
  echo "Usage: $0 <phase1_results_dir>" >&2
  exit 1
fi
DIR="$1"
FILE="$DIR/phase1-intel.json"
if [[ ! -f "$FILE" ]]; then
  log_error "phase1-intel.json missing in $DIR"
  echo "phase1-intel.json not found in $DIR" >&2
  exit 1
fi

jq -r '.hosts[] | "IP: \(.ip) Host: \(.hostname) OS: \(.os) Score: \(.score) Ports: \(.ports | join(","))"' "$FILE"
