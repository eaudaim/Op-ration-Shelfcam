#!/bin/bash
# Phase 1 reconnaissance script
# Performs rapid discovery on a network and produces structured output
# This is a simplified implementation based on user requirements.

set -u
set -o pipefail
export LANG=C
export LC_ALL=C

CONFIG_FILE="$(dirname "$0")/config-phase1.json"
if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "Missing config: $CONFIG_FILE" >&2
  exit 1
fi

# Load configuration via jq
INTERFACE=$(jq -r '.interface // ""' "$CONFIG_FILE")
BASE_DIR=$(jq -r '.base_dir // "/home/raspi3/recon"' "$CONFIG_FILE")
GLOBAL_TIMEOUT=$(jq -r '.global_timeout // 180' "$CONFIG_FILE")
ENABLE_EXTENDED=$(jq -r '.enable_extended_recon // true' "$CONFIG_FILE")
ADAPT_THRESHOLD=$(jq -r '.adaptation.large_network_threshold // 20' "$CONFIG_FILE")
ADAPT_REDUCTION=$(jq -r '.adaptation.timeout_reduction_percent // 30' "$CONFIG_FILE")
MOD_ARP=$(jq -r '.modules.arp_scan // true' "$CONFIG_FILE")
MOD_NMAP=$(jq -r '.modules.nmap // true' "$CONFIG_FILE")
MOD_MDNS=$(jq -r '.modules.mdns // true' "$CONFIG_FILE")
MOD_NETBIOS=$(jq -r '.modules.netbios // true' "$CONFIG_FILE")
MOD_TCPDUMP=$(jq -r '.modules.tcpdump // true' "$CONFIG_FILE")
MOD_TTL=$(jq -r '.modules.ttl_fingerprint // true' "$CONFIG_FILE")
MOD_RDNS=$(jq -r '.modules.reverse_dns // true' "$CONFIG_FILE")
TARGET_SCORING=$(jq -r '.modules.target_scoring // true' "$CONFIG_FILE")

ARP_TIMEOUT=$(jq -r '.timeouts.arp_scan // 45' "$CONFIG_FILE")
NBTSCAN_TIMEOUT=$(jq -r '.timeouts.nbtscan // 45' "$CONFIG_FILE")
NMAP_DISCOVERY_TIMEOUT=$(jq -r '.timeouts.nmap_discovery // 45' "$CONFIG_FILE")
NMAP_DETAILED_TIMEOUT=$(jq -r '.timeouts.nmap_detailed // 60' "$CONFIG_FILE")
TCPDUMP_TIMEOUT=$(jq -r '.timeouts.tcpdump // 60' "$CONFIG_FILE")
MDNS_TIMEOUT=$(jq -r '.timeouts.mdns // 60' "$CONFIG_FILE")
TTL_TIMEOUT=$(jq -r '.timeouts.ttl_fingerprint // 20' "$CONFIG_FILE")
RDNS_TIMEOUT=$(jq -r '.timeouts.reverse_dns // 25' "$CONFIG_FILE")

TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
OUTPUT_DIR="${BASE_DIR}/${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"
LOG_FILE="$OUTPUT_DIR/execution.log"
ERROR_LOG="$OUTPUT_DIR/error.log"

echo "[+] Output directory: $OUTPUT_DIR" | tee -a "$LOG_FILE"

# Helper for logging
log() {
  echo "[$(date '+%H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log_error(){
  echo "[$(date '+%H:%M:%S')] $1" >> "$ERROR_LOG"
}

# Check required binaries
check_binaries() {
  local miss_crit=()
  for cmd in ip jq; do
    command -v "$cmd" >/dev/null 2>&1 || miss_crit+=("$cmd")
  done
  if (( ${#miss_crit[@]} > 0 )); then
    log_error "Missing critical tools: ${miss_crit[*]}"
    echo "Cannot proceed" >&2
    exit 1
  fi
  HAVE_ARP=1; command -v arp-scan >/dev/null 2>&1 || { HAVE_ARP=0; log_error "arp-scan missing"; }
  HAVE_NMAP=1; command -v nmap >/dev/null 2>&1 || { HAVE_NMAP=0; log_error "nmap missing"; }
  HAVE_NBT=1; command -v nbtscan >/dev/null 2>&1 || { HAVE_NBT=0; log_error "nbtscan missing"; }
  HAVE_AVAHI=1; command -v avahi-browse >/dev/null 2>&1 || { HAVE_AVAHI=0; log_error "avahi-browse missing"; }
  HAVE_TCPDUMP=1; command -v tcpdump >/dev/null 2>&1 || { HAVE_TCPDUMP=0; log_error "tcpdump missing"; }
  HAVE_HOST=1; command -v host >/dev/null 2>&1 || { HAVE_HOST=0; log_error "host missing"; }
}

# Detect Wi-Fi interface
detect_interface() {
  local iface ip state
  mapfile -t wifi_ifaces < <(find /sys/class/net -type d -path "/sys/class/net/*/wireless" -printf '%h\n' 2>/dev/null | xargs -n1 basename 2>/dev/null)
  if (( ${#wifi_ifaces[@]} == 0 )); then
    INTERFACE=$(ip -o -4 route show to default | awk '{print $5}' | head -n1)
    log "No Wi-Fi interface found, defaulting to $INTERFACE"
    return
  fi
  for iface in "${wifi_ifaces[@]}"; do
    ip=$(ip -o -4 addr show "$iface" | awk '{print $4}')
    state=$(cat /sys/class/net/$iface/operstate 2>/dev/null)
    log "Found Wi-Fi iface $iface state=$state ip=${ip:-none}"
    if [[ $iface =~ ^wl(p|an) && -n $ip && $state == up ]]; then
      INTERFACE=$iface; log "Selected Wi-Fi interface: $INTERFACE"; return
    fi
  done
  for iface in "${wifi_ifaces[@]}"; do
    ip=$(ip -o -4 addr show "$iface" | awk '{print $4}')
    state=$(cat /sys/class/net/$iface/operstate 2>/dev/null)
    if [[ -n $ip && $state == up ]]; then
      INTERFACE=$iface; log "Selected Wi-Fi interface: $INTERFACE"; return
    fi
  done
  for iface in "${wifi_ifaces[@]}"; do
    state=$(cat /sys/class/net/$iface/operstate 2>/dev/null)
    if [[ $state == up ]]; then
      INTERFACE=$iface; log "Selected Wi-Fi interface without IP: $INTERFACE"; return
    fi
  done
  INTERFACE=$(ip -o -4 route show to default | awk '{print $5}' | head -n1)
  log "Fallback to default interface: $INTERFACE"
}

# Wait for IP address (non-fatal)
wait_for_ip() {
  local attempt=0
  while (( attempt < 30 )); do
    if ip -o -4 addr show "$INTERFACE" | grep -q 'inet '; then
      log "IP acquired on $INTERFACE"
      return
    fi
    log "Waiting for IP on $INTERFACE (attempt $((attempt+1)))"
    sleep 3
    attempt=$((attempt+1))
  done
  log "Proceeding without IP on $INTERFACE"
}

check_binaries
if [[ -z "$INTERFACE" ]]; then
  detect_interface
else
  log "Using interface: $INTERFACE"
fi
wait_for_ip

CIDR=$(ip -o -4 addr show "$INTERFACE" | awk '{print $4}')
NET=${CIDR:-""}

# Global timeout guard
(sleep "$GLOBAL_TIMEOUT" && echo "[!] Global timeout reached" >> "$LOG_FILE" && kill $$) &
GT_PID=$!

# ------------- Phase 1 operations -------------
# ARP scan
if [[ "$MOD_ARP" == "true" && $HAVE_ARP -eq 1 ]]; then
  log "Starting ARP scan"
  (timeout "$ARP_TIMEOUT"s arp-scan --interface "$INTERFACE" --localnet || log_error "arp-scan failed") > "$OUTPUT_DIR/arp-scan.txt" &
  ARP_PID=$!
else
  log "ARP scan disabled or missing"
  ARP_PID=0
fi

# mDNS and NetBIOS scans in parallel
if [[ "$MOD_MDNS" == "true" && $HAVE_AVAHI -eq 1 ]]; then
  (timeout "$MDNS_TIMEOUT"s avahi-browse -alr || log_error "avahi-browse failed") > "$OUTPUT_DIR/mdns.txt" &
  MDNS_PID=$!
else
  MDNS_PID=0
fi
if [[ "$MOD_NETBIOS" == "true" && $HAVE_NBT -eq 1 ]]; then
  (timeout "$NBTSCAN_TIMEOUT"s nbtscan "$NET" || log_error "nbtscan failed") > "$OUTPUT_DIR/netbios.txt" &
  NBT_PID=$!
else
  NBT_PID=0
fi

# tcpdump capture
if [[ "$MOD_TCPDUMP" == "true" && $HAVE_TCPDUMP -eq 1 ]]; then
  (timeout "$TCPDUMP_TIMEOUT"s tcpdump -p -i "$INTERFACE" -w "$OUTPUT_DIR/capture.pcap" -nn || log_error "tcpdump failed") &
  TCPDUMP_PID=$!
else
  TCPDUMP_PID=0
fi

((ARP_PID)) && wait $ARP_PID || true
((MDNS_PID)) && wait $MDNS_PID || true
((NBT_PID)) && wait $NBT_PID || true
log "Discovery scans completed"

# Parse live hosts from ARP scan
LIVE_HOSTS=$(awk '/\t/ {print $1}' "$OUTPUT_DIR/arp-scan.txt" | sort -u)
if [[ -z "$LIVE_HOSTS" ]]; then
  log "No hosts discovered"
  kill "$GT_PID" 2>/dev/null || true
  exit 0
fi

# nmap ping discovery
if [[ "$MOD_NMAP" == "true" && $HAVE_NMAP -eq 1 ]]; then
  log "Running nmap discovery"
  (timeout "$NMAP_DISCOVERY_TIMEOUT"s nmap -sn $LIVE_HOSTS -oG "$OUTPUT_DIR/nmap-live.txt" || log_error "nmap discovery failed") >/dev/null
  LIVE_HOSTS=$(awk '/Up$/ {print $2}' "$OUTPUT_DIR/nmap-live.txt" | sort -u)
else
  log "Skipping nmap discovery"
fi
live_count=$(echo "$LIVE_HOSTS" | wc -w)
log "Live hosts: $live_count"

if (( live_count > ADAPT_THRESHOLD )); then
  log "Warning: large network detected, reducing timeouts by ${ADAPT_REDUCTION}%"
  NMAP_DETAILED_TIMEOUT=$((NMAP_DETAILED_TIMEOUT*(100-ADAPT_REDUCTION)/100))
  TTL_TIMEOUT=$((TTL_TIMEOUT*(100-ADAPT_REDUCTION)/100))
  RDNS_TIMEOUT=$((RDNS_TIMEOUT*(100-ADAPT_REDUCTION)/100))
fi

# Quick nmap scan on live hosts
if [[ "$MOD_NMAP" == "true" && $HAVE_NMAP -eq 1 ]]; then
  log "Running nmap quick scan"
  (timeout "$NMAP_DETAILED_TIMEOUT"s nmap -sS -T4 -Pn $LIVE_HOSTS -oG "$OUTPUT_DIR/nmap-detailed.txt" || log_error "nmap quick scan failed") >/dev/null
else
  log "Skipping nmap quick scan"
fi

# TTL fingerprinting
if [[ "$MOD_TTL" == "true" ]]; then
  log "TTL fingerprinting"
  : > "$OUTPUT_DIR/os-fingerprint.txt"
  for ip in $LIVE_HOSTS; do
    ttl=$(timeout "$TTL_TIMEOUT"s ping -c1 -W1 "$ip" 2>/dev/null | awk -F"ttl=" '/ttl=/{print $2}' | awk '{print $1}')
    os="unknown"
    case "$ttl" in
      64) os="linux" ;;
      128) os="windows" ;;
      255) os="network" ;;
    esac
    echo "$ip $os" >> "$OUTPUT_DIR/os-fingerprint.txt"
  done
else
  log "TTL fingerprinting disabled"
fi

# Reverse DNS
if [[ "$MOD_RDNS" == "true" && $HAVE_HOST -eq 1 ]]; then
  log "Reverse DNS lookups"
  : > "$OUTPUT_DIR/reverse-dns.txt"
  for ip in $LIVE_HOSTS; do
    host="$(timeout "${RDNS_TIMEOUT}"s host "$ip" 2>/dev/null | awk '{print $5}' | sed 's/\.$//')"
    echo "$ip ${host:-unknown}" >> "$OUTPUT_DIR/reverse-dns.txt"
  done
else
  log "Reverse DNS disabled"
fi

# Port summary
declare -A PORTS
if [[ -f "$OUTPUT_DIR/nmap-detailed.txt" ]]; then
  log "Summarising ports"
  : > "$OUTPUT_DIR/port-summary.txt"
  while read -r line; do
    ip=$(echo "$line" | awk '{print $2}')
    ports=$(echo "$line" | awk -F"Ports: " '{print $2}')
    [[ -z "$ip" || -z "$ports" ]] && continue
    PORTS[$ip]=$(echo "$ports" | sed 's#/open/[^ ]*//##g' | sed 's/,/ /g')
    echo "$ip ${PORTS[$ip]}" >> "$OUTPUT_DIR/port-summary.txt"
  done < <(grep "Ports:" "$OUTPUT_DIR/nmap-detailed.txt")
else
  log "No nmap detailed results; port summary skipped"
fi

((TCPDUMP_PID)) && wait $TCPDUMP_PID || true
if [[ -f "$OUTPUT_DIR/capture.pcap" ]]; then
  log "Analyzing captured traffic"
  {
    echo "Top protocols:"
    tcpdump -nn -r "$OUTPUT_DIR/capture.pcap" 2>/dev/null | awk '{print $2}' | sort | uniq -c | sort -nr | head -n 10
    echo
    echo "Top IPs:"
    tcpdump -nn -r "$OUTPUT_DIR/capture.pcap" 2>/dev/null | awk '/ IP /{print $3; print $5}' | sed 's/://g' | awk -F. '{print $1"."$2"."$3"."$4}' | sort | uniq -c | sort -nr | head -n 10
  } > "$OUTPUT_DIR/traffic-analysis.txt"
else
  log "No capture file for analysis"
fi

# Target scoring
if [[ "$TARGET_SCORING" == "true" ]]; then
  log "Scoring targets"
  : > "$OUTPUT_DIR/targets-scored.txt"
  while read -r ip; do
    score=0
    reasons=()
    ports=${PORTS[$ip]}
    for p in $ports; do
      case "$p" in
        22*) score=$((score+10)); reasons+=("SSH") ;;
        80*|443*) score=$((score+8)); reasons+=("HTTP") ;;
        139*|445*) score=$((score+15)); reasons+=("SMB") ;;
        21*|23*) score=$((score+5)); reasons+=("FTP/Telnet") ;;
        161*) score=$((score+15)); reasons+=("SNMP") ;;
        3389*) score=$((score+10)); reasons+=("RDP") ;;
        5900*) score=$((score+8)); reasons+=("VNC") ;;
      esac
    done
    # OS points
    os=$(grep "^$ip " "$OUTPUT_DIR/os-fingerprint.txt" | awk '{print $2}')
    case "$os" in
      windows) score=$((score+10)); reasons+=("Windows") ;;
      linux) score=$((score+5)); reasons+=("Linux") ;;
      network) score=$((score+12)); reasons+=("Network gear") ;;
    esac
    # More than 5 ports
    port_count=$(echo "$ports" | wc -w)
    if (( port_count > 5 )); then
      score=$((score+8)); reasons+=(">5 ports")
    fi
    # Hostname keywords
    host="unknown"
    if [[ -f "$OUTPUT_DIR/reverse-dns.txt" ]]; then
      host=$(grep "^$ip " "$OUTPUT_DIR/reverse-dns.txt" | awk '{print $2}')
    fi
    if echo "$host" | grep -Eiq '(server|admin|router|printer)'; then
      score=$((score+5)); reasons+=("hostname")
    fi
    printf "%s:%d:%s\n" "$ip" "$score" "$(IFS=,;echo "${reasons[*]}")" >> "$OUTPUT_DIR/targets-scored.txt"
  done <<< "$LIVE_HOSTS"
fi

# Build phase1-intel.json
log "Building intel summary"
{ 
  echo '{"hosts":['
  first=1
  while read -r ip; do
    host="unknown"
    if [[ -f "$OUTPUT_DIR/reverse-dns.txt" ]]; then
      host=$(grep "^$ip " "$OUTPUT_DIR/reverse-dns.txt" | awk '{print $2}')
    fi
    os=$(grep "^$ip " "$OUTPUT_DIR/os-fingerprint.txt" | awk '{print $2}')
    ports="${PORTS[$ip]}"
    score=$(grep "^$ip:" "$OUTPUT_DIR/targets-scored.txt" | awk -F: '{print $2}')
    os_conf=0.0
    host_conf=0.0
    case "$os" in
      windows|linux) os_conf=0.8 ;;
      network) os_conf=0.9 ;;
    esac
    [[ -n $host && $host != unknown ]] && host_conf=0.7
    recs=()
    [[ $ports =~ 445 ]] && recs+=("smb_enum")
    [[ $ports =~ 161 ]] && recs+=("snmp_scan")
    [[ $ports =~ 80 || $ports =~ 443 ]] && recs+=("banner_grab")
    [[ $ports =~ 22 ]] && recs+=("ssh_enum")
    recs_json=$(printf '"%s",' "${recs[@]}")
    recs_json=${recs_json%,}
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    [[ $first -eq 1 ]] || echo ','
    first=0
    printf '{"ip":"%s","hostname":"%s","os":"%s","ports":[%s],"score":%s,"confidence":{"os":%.1f,"hostname":%.1f},"timestamp":"%s","recommendations":[%s]}' \
      "$ip" "${host:-}" "${os:-}" "$(echo "$ports" | sed 's/ /, /g')" "${score:-0}" "$os_conf" "$host_conf" "$ts" "$recs_json"
  done <<< "$LIVE_HOSTS"
  echo ']}'
} > "$OUTPUT_DIR/phase1-intel.json"

# Recommend strategy
if (( live_count <= 8 )); then
  rec="intensive"
elif (( live_count <= 15 )); then
  rec="selective"
else
  rec="minimal"
fi

echo "$rec" > "$OUTPUT_DIR/recommended-phase2.txt"
log "Recommended Phase 2 strategy: $rec"

kill "$GT_PID" 2>/dev/null || true
log "Phase 1 complete"
