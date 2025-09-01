#!/bin/bash
#
# Script de reconnaissance réseau Red Team - Version améliorée
# Exécution automatique au boot du Raspberry Pi
# Auteur: Red Team Exercise  
# Version: 2.0
#

# Sécurisation et normalisation
set -euo pipefail
umask 077
export LANG=C
export LC_ALL=C

# Configuration
INTERFACE=""  # Auto-détection
BASE_DIR="/home/pi/recon"
TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
OUTPUT_DIR="${BASE_DIR}/${TIMESTAMP}"
LOG_FILE="${OUTPUT_DIR}/execution.log"
GLOBAL_TIMEOUT=600  # 10 minutes
LOCK="/var/run/recon.lock"

# Options d'activation des modules
ENABLE_MDNS=1
ENABLE_NETBIOS=1  
ENABLE_TCPDUMP=1

# Gestion du lockfile
if [ -e "$LOCK" ]; then
    echo "[$(date)] Lock présent, autre instance en cours. Sortie." | tee -a /tmp/recon_conflict.log
    exit 0
fi
trap 'rm -f "$LOCK"' EXIT
touch "$LOCK"

# Vérification root obligatoire
if [ "$EUID" -ne 0 ]; then
    echo "Ce script doit être exécuté en root pour fonctionner correctement" | tee -a /tmp/recon_error.log
    exit 1
fi

# Création du répertoire de sortie
mkdir -p "$OUTPUT_DIR"

# Fonction de logging
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

# Vérification des binaires requis
check_binaries() {
    log "Vérification des outils requis..."
    
    local missing=0
    for bin in ip nmap arp-scan tcpdump iw; do
        if ! command -v "$bin" >/dev/null 2>&1; then
            log "ERREUR: $bin introuvable - installation requise"
            ((missing++))
        fi
    done
    
    # Outils optionnels
    for bin in nbtscan avahi-browse; do
        if ! command -v "$bin" >/dev/null 2>&1; then
            log "WARN: $bin introuvable - module désactivé"
        fi
    done
    
    if [ $missing -gt 0 ]; then
        log "ARRÊT: $missing outil(s) obligatoire(s) manquant(s)"
        exit 1
    fi
    
    log "Vérification des outils: OK"
}

# Auto-détection de l'interface Wi-Fi active
detect_wifi_interface() {
    log "Auto-détection de l'interface Wi-Fi..."
    
    # Recherche des interfaces Wi-Fi connectées avec IP
    for iface in $(ls /sys/class/net/ | grep -E '^(wlan|wlp)'); do
        if [ -d "/sys/class/net/$iface/wireless" ]; then
            if ip -o -4 addr show "$iface" | grep -q 'inet ' && ip link show "$iface" | grep -q 'state UP'; then
                INTERFACE="$iface"
                log "Interface Wi-Fi active détectée: $INTERFACE"
                return 0
            fi
        fi
    done
    
    # Fallback: première interface Wi-Fi UP
    for iface in $(ls /sys/class/net/ | grep -E '^(wlan|wlp)'); do
        if [ -d "/sys/class/net/$iface/wireless" ] && ip link show "$iface" | grep -q 'state UP'; then
            INTERFACE="$iface"
            log "Interface Wi-Fi UP trouvée: $INTERFACE (sans IP)"
            return 0
        fi
    done
    
    log "ERREUR: Aucune interface Wi-Fi active détectée"
    return 1
}

# Attente d'une IP sur l'interface Wi-Fi
wait_for_ip() {
    local max_attempts=30 
    local attempt=1
    
    log "Attente d'une IP sur $INTERFACE..."
    
    while [ $attempt -le $max_attempts ]; do
        if ip -o -4 addr show "$INTERFACE" | grep -q 'inet '; then
            log "IP détectée sur $INTERFACE (tentative $attempt)"
            # Vérification optionnelle de la route par défaut
            if ip route | grep -q '^default '; then
                log "Route par défaut détectée"
            else
                log "Pas de route par défaut (réseau local uniquement)"
            fi
            return 0
        fi
        
        log "Pas d'IP sur $INTERFACE (tentative $attempt/$max_attempts). Attente 3s..."
        sleep 3
        ((attempt++))
    done
    
    log "ERREUR: Pas d'IP sur $INTERFACE après $max_attempts tentatives"
    return 1
}

# Fonction pour obtenir les informations réseau
get_network_info() {
    log "Collecte des informations réseau..."
    
    {
        echo "=== INFORMATIONS RÉSEAU ==="
        echo "Date/Heure: $(date)"
        echo "Interface utilisée: $INTERFACE"
        echo ""
        
        echo "=== INTERFACES RÉSEAU ==="
        ip addr show
        echo ""
        
        echo "=== TABLE DE ROUTAGE ==="
        ip route show
        echo ""
        
        echo "=== RÉSOLUTION DNS ==="
        cat /etc/resolv.conf 2>/dev/null || echo "Pas de resolv.conf"
        echo ""
        
        echo "=== HOSTNAME ==="
        hostname
        echo ""
        
        echo "=== INFORMATIONS Wi-Fi (iw) ==="
        iw dev "$INTERFACE" info 2>/dev/null || echo "Info iw non disponible"
        echo ""
        iw "$INTERFACE" link 2>/dev/null || echo "Link iw non disponible"
        echo ""
        
        echo "=== VARIABLES D'ENVIRONNEMENT RÉSEAU ==="
        env | grep -E "(IP|DNS|GATEWAY|NETWORK)" || echo "Aucune variable réseau détectée"
        
    } > "$OUTPUT_DIR/info.txt"
    
    log "Informations réseau collectées"
}

# Détection propre du CIDR réseau
get_target_network() {
    local cidr
    
    # Récupération du CIDR exact de l'interface
    cidr=$(ip -o -4 addr show "$INTERFACE" | awk '{print $4}' | head -n1)
    
    if [ -n "$cidr" ]; then
        # Conversion en réseau (ex: 192.168.1.50/24 -> 192.168.1.0/24)
        local ip_part=$(echo "$cidr" | cut -d'/' -f1)
        local prefix=$(echo "$cidr" | cut -d'/' -f2)
        local network=$(ipcalc -n "$cidr" 2>/dev/null | cut -d'=' -f2 2>/dev/null || echo "")
        
        if [ -n "$network" ]; then
            echo "$network/$prefix"
        else
            # Fallback manuel pour /24
            if [ "$prefix" = "24" ]; then
                local subnet=$(echo "$ip_part" | cut -d'.' -f1-3)
                echo "$subnet.0/24"
            else
                echo "$cidr"
            fi
        fi
    else
        # Dernier fallback via route par défaut
        local gateway=$(ip route | awk '/^default/ {print $3}' | head -n1)
        if [ -n "$gateway" ]; then
            local subnet=$(echo "$gateway" | cut -d'.' -f1-3)
            echo "$subnet.0/24"
        else
            echo ""
        fi
    fi
}

# Scan ARP optimisé
arp_scan() {
    log "Lancement d'arp-scan..."
    
    local target_network=$(get_target_network)
    if [ -n "$target_network" ]; then
        log "arp-scan sur $target_network"
        timeout 60 arp-scan --interface="$INTERFACE" "$target_network" > "$OUTPUT_DIR/arp-scan.txt" 2>&1
    else
        timeout 60 arp-scan --localnet --interface="$INTERFACE" > "$OUTPUT_DIR/arp-scan.txt" 2>&1
    fi
    
    local exit_code=$?
    log "arp-scan terminé (code: $exit_code)"
}

# Scan NetBIOS conditionnel
netbios_scan() {
    if [ "$ENABLE_NETBIOS" -ne 1 ] || ! command -v nbtscan >/dev/null 2>&1; then
        log "NetBIOS scan désactivé ou nbtscan indisponible"
        echo "NetBIOS scan désactivé" > "$OUTPUT_DIR/nbtscan.txt"
        return
    fi
    
    log "Lancement de nbtscan..."
    
    local target_network=$(get_target_network)
    if [ -n "$target_network" ]; then
        log "nbtscan sur $target_network"
        timeout 90 nbtscan -n "$target_network" > "$OUTPUT_DIR/nbtscan.txt" 2>&1
    else
        log "ERREUR: Réseau cible non détecté pour nbtscan"
        echo "ERREUR: Réseau non détecté" > "$OUTPUT_DIR/nbtscan.txt"
    fi
    
    log "nbtscan terminé"
}

# Découverte mDNS conditionnelle
mdns_scan() {
    if [ "$ENABLE_MDNS" -ne 1 ] || ! command -v avahi-browse >/dev/null 2>&1; then
        log "mDNS scan désactivé ou avahi-browse indisponible"
        echo "mDNS scan désactivé" > "$OUTPUT_DIR/mdns.txt"
        return
    fi
    
    log "Lancement d'avahi-browse..."
    timeout 60 avahi-browse -a -t > "$OUTPUT_DIR/mdns.txt" 2>&1
    log "Découverte mDNS terminée"
}

# Scan Nmap intelligent (2 étapes)
nmap_scan() {
    log "Lancement du scan nmap intelligent..."
    
    local target_network=$(get_target_network)
    if [ -z "$target_network" ]; then
        log "ERREUR: Réseau cible non détecté pour nmap"
        echo "ERREUR: Réseau non détecté" > "$OUTPUT_DIR/nmap-error.txt"
        return
    fi
    
    log "Scan nmap sur $target_network"
    cd "$OUTPUT_DIR"
    
    # Étape 1: Découverte d'hôtes (ping scan)
    log "Étape 1: Découverte d'hôtes vivants..."
    timeout 60 nmap -n -sn -e "$INTERFACE" "$target_network" -oG hosts.gnmap >/dev/null 2>&1
    
    # Extract live hosts
    local live_hosts
    live_hosts=$(awk '/Up$/{print $2}' hosts.gnmap 2>/dev/null | tr '\n' ' ' | sed 's/[[:space:]]*$//')
    
    if [ -n "$live_hosts" ]; then
        local host_count
        host_count=$(echo "$live_hosts" | wc -w)
        log "Étape 2: Scan détaillé de $host_count hôte(s) vivant(s)..."
        
        # Étape 2: Scan détaillé des hôtes vivants uniquement
        timeout 300 nmap -n -T3 -F -O -sC -e "$INTERFACE" \
            -oA nmap-live -oN nmap-live.txt \
            $live_hosts >/dev/null 2>&1
        
        log "Scan nmap terminé sur $host_count hôtes"
    else
        log "Aucun hôte vivant détecté, scan complet du réseau..."
        # Fallback: scan complet mais rapide
        timeout 200 nmap -n -T3 --top-ports 100 -e "$INTERFACE" \
            -oA nmap-fallback -oN nmap-fallback.txt \
            "$target_network" >/dev/null 2>&1
        log "Scan nmap fallback terminé"
    fi
}

# Capture réseau passive conditionnelle
network_capture() {
    if [ "$ENABLE_TCPDUMP" -ne 1 ]; then
        log "Capture tcpdump désactivée"
        return
    fi
    
    log "Démarrage de la capture réseau passive (120s)..."
    
    # Capture optimisée sans résolution DNS
    timeout 125 tcpdump -i "$INTERFACE" -nn -s 0 -w "$OUTPUT_DIR/tcpdump.pcap" -G 120 -W 1 >/dev/null 2>&1
    
    log "Capture réseau terminée"
}

# Finalisation et génération du résumé
finalize() {
    log "Finalisation..."
    
    # Comptage des hôtes vivants
    local live_count=0
    if [ -f "$OUTPUT_DIR/hosts.gnmap" ]; then
        live_count=$(awk '/Up$/' "$OUTPUT_DIR/hosts.gnmap" 2>/dev/null | wc -l)
    fi
    
    {
        echo "=== RÉSUMÉ DE LA RECONNAISSANCE ==="
        echo "Date: $(date)"
        echo "Durée totale: $SECONDS secondes"
        echo "Interface: $INTERFACE"
        echo "Réseau cible: $(get_target_network)"
        echo "Hôtes vivants détectés: $live_count"
        echo "Répertoire: $OUTPUT_DIR"
        echo ""
        
        echo "=== FICHIERS GÉNÉRÉS ==="
        ls -la "$OUTPUT_DIR" 2>/dev/null || echo "Erreur listage fichiers"
        echo ""
        
        echo "=== TAILLES DES FICHIERS ==="
        du -h "$OUTPUT_DIR"/* 2>/dev/null | sort -rh || echo "Erreur calcul tailles"
        echo ""
        
        echo "=== CONFIGURATION UTILISÉE ==="
        echo "ENABLE_MDNS: $ENABLE_MDNS"
        echo "ENABLE_NETBIOS: $ENABLE_NETBIOS"
        echo "ENABLE_TCPDUMP: $ENABLE_TCPDUMP"
        echo "GLOBAL_TIMEOUT: ${GLOBAL_TIMEOUT}s"
        
    } > "$OUTPUT_DIR/resume.txt"
    
    log "Script de reconnaissance terminé avec succès"
    log "Fichiers disponibles dans: $OUTPUT_DIR"
    log "Hôtes vivants détectés: $live_count"
}

# Fonction principale
main() {
    local start_time
    start_time=$(date +%s)
    
    log "=== DÉBUT DE LA RECONNAISSANCE RÉSEAU V2.0 ==="
    log "PID: $$"
    log "Timeout global: ${GLOBAL_TIMEOUT}s"
    log "Répertoire de sortie: $OUTPUT_DIR"
    
    # Vérifications préalables
    check_binaries
    
    # Auto-détection de l'interface Wi-Fi
    if ! detect_wifi_interface; then
        log "ARRÊT: Aucune interface Wi-Fi disponible"
        exit 1
    fi
    
    # Attente d'une IP (non bloquant pour Internet)
    if ! wait_for_ip; then
        log "ATTENTION: Pas d'IP détectée, tentative de scan sur interface"
    fi
    
    # Pause de stabilisation
    log "Pause de stabilisation (5s)..."
    sleep 5
    
    # Collecte des informations système
    get_network_info
    
    # Lancement des scans en parallèle
    log "Lancement des scans de découverte..."
    
    # Scans rapides en parallèle
    arp_scan &
    ARP_PID=$!
    
    if [ "$ENABLE_NETBIOS" -eq 1 ]; then
        netbios_scan &
        NETBIOS_PID=$!
    fi
    
    if [ "$ENABLE_MDNS" -eq 1 ]; then
        mdns_scan &
        MDNS_PID=$!
    fi
    
    # Scan nmap (plus long) en parallèle
    nmap_scan &
    NMAP_PID=$!
    
    # Capture réseau en arrière-plan
    if [ "$ENABLE_TCPDUMP" -eq 1 ]; then
        network_capture &
        CAPTURE_PID=$!
    fi
    
    # Attente des scans de découverte
    wait $ARP_PID || log "arp_scan terminé avec erreur"
    
    if [ -n "${NETBIOS_PID:-}" ]; then
        wait $NETBIOS_PID || log "netbios_scan terminé avec erreur"
    fi
    
    if [ -n "${MDNS_PID:-}" ]; then
        wait $MDNS_PID || log "mdns_scan terminé avec erreur"
    fi
    
    log "Scans de découverte terminés"
    
    # Attente du scan nmap
    wait $NMAP_PID || log "nmap_scan terminé avec erreur"
    log "Scan nmap terminé"
    
    # Attente de la capture
    if [ -n "${CAPTURE_PID:-}" ]; then
        wait $CAPTURE_PID || log "network_capture terminé avec erreur"
        log "Capture réseau terminée"
    fi
    
    # Calcul du temps d'exécution
    local end_time
    end_time=$(date +%s)
    SECONDS=$((end_time - start_time))
    
    # Finalisation
    finalize
    
    log "=== FIN DE LA RECONNAISSANCE (${SECONDS}s) ==="
}

# Fonction de timeout global
global_timeout() {
    sleep "$GLOBAL_TIMEOUT"
    log "TIMEOUT GLOBAL: Arrêt forcé du script après ${GLOBAL_TIMEOUT}s"
    pkill -P $$ 2>/dev/null || true
    exit 124
}

# Gestion des signaux
trap 'log "Signal reçu, arrêt propre du script"; rm -f "$LOCK"; exit 130' INT TERM

# Lancement du timeout global en arrière-plan
global_timeout &
TIMEOUT_PID=$!

# Lancement du script principal
main

# Arrêt du timeout si le script se termine normalement
kill $TIMEOUT_PID 2>/dev/null || true

exit 0
