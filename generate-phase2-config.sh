#!/bin/bash
# Generate Phase 2 configuration based on Phase 1 output

set -u
set -o pipefail

ERROR_LOG="error.log"
log_error(){ echo "[$(date '+%H:%M:%S')] $1" >> "$ERROR_LOG"; }

if [[ $# -ne 1 ]]; then
  log_error "usage: generate-phase2-config <dir>"
  echo "Usage: $0 <phase1_results_dir>" >&2
  exit 1
fi

P1_DIR="$1"
if [[ ! -d "$P1_DIR" ]]; then
  log_error "directory not found: $P1_DIR"
  echo "Directory not found: $P1_DIR" >&2
  exit 1
fi

STRATEGY="$(cat "$P1_DIR/recommended-phase2.txt" 2>/dev/null || echo minimal)"

cat > "$P1_DIR/config-phase2.json" <<CFG
{
  "mode": "phase2",
  "phase1_results_path": "$P1_DIR",
  "strategy": "$STRATEGY",
  "global_timeout": 180,
  "max_targets": 5,
  "focus_areas": ["banner_grab", "smb_enum", "snmp_scan", "vuln_hints"]
}
CFG

echo "Created $P1_DIR/config-phase2.json with strategy $STRATEGY"
