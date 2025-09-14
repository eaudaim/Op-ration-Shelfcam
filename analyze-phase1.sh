#!/bin/bash
# Offline analyzer for Phase 1 results

set -u
set -o pipefail

ERROR_LOG="error.log"
log_error(){ echo "[$(date '+%H:%M:%S')] $1" >> "$ERROR_LOG"; }

if [[ $# -ne 1 ]]; then
  log_error "usage: analyze-phase1 <dir>"
  echo "Usage: $0 <phase1_results_dir>" >&2
  exit 1
fi
DIR="$1"
FILE="$DIR/targets-scored.txt"
if [[ ! -f "$FILE" ]]; then
  log_error "targets-scored.txt missing in $DIR"
  echo "targets-scored.txt not found in $DIR" >&2
  exit 1
fi

echo "Top targets:" 
sort -t: -k2 -nr "$FILE" | head -n 10
