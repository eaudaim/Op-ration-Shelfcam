#!/bin/bash
# Simple target re-scoring/filtering tool

set -u
set -o pipefail

ERROR_LOG="error.log"
log_error(){ echo "[$(date '+%H:%M:%S')] $1" >> "$ERROR_LOG"; }

if [[ $# -lt 1 ]]; then
  log_error "usage: target-prioritizer <dir> [min]"
  echo "Usage: $0 <phase1_results_dir> [min_score]" >&2
  exit 1
fi
DIR="$1"
MIN=${2:-0}
FILE="$DIR/targets-scored.txt"
if [[ ! -f "$FILE" ]]; then
  log_error "targets-scored.txt missing in $DIR"
  echo "targets-scored.txt not found in $DIR" >&2
  exit 1
fi

awk -F: -v m="$MIN" '$2>=m' "$FILE" | sort -t: -k2 -nr
