#!/bin/bash
# Phase 2 reconnaissance script
# Reads Phase 1 results and performs targeted enumeration

set -u
set -o pipefail
export LANG=C
export LC_ALL=C

CONFIG_FILE="${1:-$(dirname "$0")/config-phase2.json}"
if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "Config file missing: $CONFIG_FILE" >&2
  exit 1
fi

PHASE1_DIR=$(jq -r '.phase1_results_path' "$CONFIG_FILE")
STRATEGY=$(jq -r '.strategy // "auto"' "$CONFIG_FILE")
GLOBAL_TIMEOUT=$(jq -r '.global_timeout // 180' "$CONFIG_FILE")
MAX_TARGETS=$(jq -r '.max_targets // 5' "$CONFIG_FILE")
FOCUS=$(jq -r '.focus_areas[]?' "$CONFIG_FILE")

TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
OUT_DIR="$PHASE1_DIR/phase2-${TIMESTAMP}"
mkdir -p "$OUT_DIR"
LOG_FILE="$OUT_DIR/execution.log"
ERROR_LOG="$OUT_DIR/error.log"

log(){ echo "[$(date '+%H:%M:%S')] $1" | tee -a "$LOG_FILE"; }
log_error(){ echo "[$(date '+%H:%M:%S')] $1" >> "$ERROR_LOG"; }

# allow up to 3 concurrent tasks
run_limited(){
  while (( $(jobs -pr | wc -l) >= 3 )); do
    wait -n 2>/dev/null || wait
  done
  "$@" &
}

log "Output directory: $OUT_DIR"

check_tools(){
  HAVE_NMAP=1; command -v nmap >/dev/null 2>&1 || { HAVE_NMAP=0; log_error "nmap missing"; }
  HAVE_CURL=1; command -v curl >/dev/null 2>&1 || { HAVE_CURL=0; log_error "curl missing"; }
  HAVE_SMBCLIENT=1; command -v smbclient >/dev/null 2>&1 || { HAVE_SMBCLIENT=0; log_error "smbclient missing"; }
  HAVE_SNMPWALK=1; command -v snmpwalk >/dev/null 2>&1 || { HAVE_SNMPWALK=0; log_error "snmpwalk missing"; }
  HAVE_SSH=1; command -v ssh >/dev/null 2>&1 || { HAVE_SSH=0; log_error "ssh missing"; }
  HAVE_FTP=1; command -v ftp >/dev/null 2>&1 || { HAVE_FTP=0; log_error "ftp missing"; }
  HAVE_NC=1; command -v nc >/dev/null 2>&1 || { HAVE_NC=0; log_error "nc missing"; }
}

check_tools

(sleep "$GLOBAL_TIMEOUT" && log "Global timeout reached" && kill $$) &
GT_PID=$!

# Determine strategy if auto
if [[ "$STRATEGY" == "auto" ]]; then
  if [[ -f "$PHASE1_DIR/recommended-phase2.txt" ]]; then
    STRATEGY=$(cat "$PHASE1_DIR/recommended-phase2.txt")
  else
    STRATEGY="minimal"
  fi
fi
log "Using strategy: $STRATEGY"

# Load targets sorted by score
TARGETS_FILE="$PHASE1_DIR/targets-scored.txt"
if [[ ! -f "$TARGETS_FILE" ]]; then
  log "targets-scored.txt not found"
  kill "$GT_PID" 2>/dev/null || true
  exit 1
fi

mapfile -t TARGETS < <(sort -t: -k2 -nr "$TARGETS_FILE" | awk -F: '{print $1 ":" $3}' )

target_limit=$MAX_TARGETS
case "$STRATEGY" in
  intensive) target_limit=$MAX_TARGETS ;;
  selective) target_limit=5 ;;
  minimal)   target_limit=3 ;;
  *) target_limit=$MAX_TARGETS ;;
esac

# enumeration helpers
nmap_scan(){
  local ip="$1" ports="$2"
  log "Scanning $ip ports: $ports"
  timeout 60s nmap -sV -Pn -p "$ports" "$ip" -oN "$OUT_DIR/nmap-$ip.txt" >/dev/null 2>&1 || log_error "nmap scan failed on $ip"
}

smb_enum(){
  local ip="$1"
  timeout 20s smbclient -L "//$ip" -N > "$OUT_DIR/smb-$ip.txt" 2>&1 || log_error "smbclient failed on $ip"
}

snmp_enum(){
  local ip="$1"
  timeout 20s snmpwalk -v2c -c public "$ip" 1.3.6.1.2.1.1 > "$OUT_DIR/snmp-$ip.txt" 2>&1 || log_error "snmpwalk failed on $ip"
}

http_enum(){
  local ip="$1" port="$2" proto="http"
  [[ "$port" == "443" ]] && proto="https"
  local out="$OUT_DIR/http-$ip-$port.txt"
  timeout 8s curl -skD - "$proto://$ip:$port" -o /dev/null > "$out" 2>&1 || log_error "curl failed on $ip:$port"
  timeout 8s curl -sk "$proto://$ip:$port" | grep -Eio 'wordpress|drupal|joomla|magento' | head -n1 >> "$out" 2>/dev/null || true
  local rc
  rc=$(timeout 5s curl -sk -o /dev/null -w '%{http_code}' "$proto://$ip:$port/robots.txt" 2>/dev/null || true)
  echo "robots:$rc" >> "$out"
}

ssh_enum(){
  local ip="$1" port="$2" out="$OUT_DIR/ssh-$ip-$port.txt"
  timeout 8s ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 -p "$port" "$ip" -vvv </dev/null > "$out" 2>&1 || log_error "ssh enumeration failed on $ip"
}

ftp_enum(){
  local ip="$1" port="$2" out="$OUT_DIR/ftp-$ip-$port.txt"
  timeout 8s nc -vn "$ip" "$port" < /dev/null > "$out" 2>&1 || log_error "nc failed on $ip:$port"
  timeout 8s ftp -inv "$ip" "$port" <<EOF >> "$out" 2>&1
user anonymous anonymous
quit
EOF
}

generic_banner(){
  local ip="$1" port="$2" out="$OUT_DIR/banner-$ip-$port.txt"
  timeout 5s nc -vn "$ip" "$port" < /dev/null > "$out" 2>&1 || log_error "nc banner grab failed on $ip:$port"
}

detect_monitoring(){
  [[ $HAVE_NMAP -eq 1 ]] || { log "Monitoring check skipped"; return; }
  log "Checking for monitoring solutions"
  local out="$OUT_DIR/monitoring-check.txt"
  : > "$out"
  local ips
  ips=$(awk -F: '{print $1}' "$TARGETS_FILE" | head -n $target_limit)
  [[ -z "$ips" ]] && return
  timeout 60s nmap -sS -Pn -T1 -p 161,514,1514 $ips >> "$out" 2>&1 || log_error "monitoring port scan failed"
  timeout 60s nmap -sn $ips >> "$out" 2>&1 || log_error "monitoring discovery failed"
  echo -e "\nIndicators:" >> "$out"
  grep -Ei 'Fortinet|Check Point|Checkpoint|Palo Alto|honeypot' "$out" >> "$out" || true
}

vulnerability_scanning(){
  log "Generating vulnerability hints"
  local out="$OUT_DIR/vulnerability-hints.txt"
  : > "$out"
  for f in "$OUT_DIR"/nmap-*.txt "$OUT_DIR"/http-*.txt "$OUT_DIR"/banner-*.txt "$OUT_DIR"/ssh-*.txt "$OUT_DIR"/ftp-*.txt; do
    [[ -f "$f" ]] || continue
    grep -Eqi 'OpenSSH_([0-6]\.|7\.0)' "$f" && echo "$f: outdated OpenSSH" >> "$out"
    grep -Eqi 'Apache/2\.[0-3]' "$f" && echo "$f: outdated Apache" >> "$out"
  done
  while read -r ip ports; do
    for p in $ports; do
      case "$p" in
        21|22|23|25|53|80|110|139|143|161|443|445|3389|5900) : ;;
        *) echo "$ip service on uncommon port $p" >> "$out" ;;
      esac
    done
  done < "$PHASE1_DIR/port-summary.txt"
  if [[ $HAVE_CURL -eq 1 ]]; then
    for ip in $(awk -F: '{print $1}' "$TARGETS_FILE" | head -n $target_limit); do
      for proto in http https; do
        code=$(timeout 5s curl -sk -u admin:admin -o /dev/null -w '%{http_code}' "$proto://$ip" 2>/dev/null || true)
        [[ "$code" == "200" ]] && echo "$ip ($proto) accepts admin/admin" >> "$out"
      done
    done
  fi
}

final_report(){
  local out="$OUT_DIR/final-report.txt"
  {
    echo "=== Phase 1 Targets ==="
    if [[ -f "$PHASE1_DIR/targets-scored.txt" ]]; then
      sort -t: -k2 -nr "$PHASE1_DIR/targets-scored.txt" | head -n 10
    fi
    echo
    echo "=== Phase 2 Findings ==="
    for f in "$OUT_DIR"/nmap-*.txt "$OUT_DIR"/http-*.txt "$OUT_DIR"/ssh-*.txt "$OUT_DIR"/ftp-*.txt "$OUT_DIR"/banner-*.txt; do
      [[ -f "$f" ]] || continue
      echo "--- $(basename "$f") ---"
      head -n 5 "$f"
    done
    echo
    if [[ -f "$OUT_DIR/vulnerability-hints.txt" ]]; then
      echo "=== Vulnerability Hints ==="
      cat "$OUT_DIR/vulnerability-hints.txt"
    fi
    echo
    echo "Next steps: review high scoring targets for exploitation."
  } > "$out"
}

# Load port information
declare -A PORTS
while read -r ip ports; do
  PORTS[$ip]="$ports"
done < "$PHASE1_DIR/port-summary.txt"

count=0
has_banner=$(echo "$FOCUS" | grep -q 'banner_grab' && echo 1 || echo 0)
has_smb=$(echo "$FOCUS" | grep -q 'smb_enum' && echo 1 || echo 0)
has_snmp=$(echo "$FOCUS" | grep -q 'snmp_scan' && echo 1 || echo 0)
for entry in "${TARGETS[@]}"; do
  ip=${entry%%:*}
  ports=${PORTS[$ip]}
  [[ -z "$ports" ]] && continue
  [[ $HAVE_NMAP -eq 1 ]] && run_limited nmap_scan "$ip" "$ports" || log "Skipping nmap for $ip"
  for p in $ports; do
    case "$p" in
      80|443)
        ((has_banner)) && [[ $HAVE_CURL -eq 1 ]] && run_limited http_enum "$ip" "$p"
        ;;
      22)
        ((has_banner)) && [[ $HAVE_SSH -eq 1 ]] && run_limited ssh_enum "$ip" "$p"
        ;;
      21)
        ((has_banner)) && [[ $HAVE_FTP -eq 1 && $HAVE_NC -eq 1 ]] && run_limited ftp_enum "$ip" "$p"
        ;;
      445)
        ((has_smb)) && [[ $HAVE_SMBCLIENT -eq 1 ]] && run_limited smb_enum "$ip"
        ;;
      161)
        ((has_snmp)) && [[ $HAVE_SNMPWALK -eq 1 ]] && run_limited snmp_enum "$ip"
        ;;
      *)
        ((has_banner)) && [[ $HAVE_NC -eq 1 ]] && run_limited generic_banner "$ip" "$p"
        ;;
    esac
  done
  ((count++))
  [[ $count -ge $target_limit ]] && break
done
wait
detect_monitoring
vulnerability_scanning
final_report

kill "$GT_PID" 2>/dev/null || true
log "Phase 2 complete"
