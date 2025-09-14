#!/bin/bash
set -euo pipefail

if [ "$EUID" -ne 0 ]; then
    echo "Ce script doit être exécuté en root." >&2
    exit 1
fi

if ! command -v apt-get >/dev/null 2>&1; then
    echo "Gestionnaire de paquets 'apt-get' introuvable. Installation manuelle requise." >&2
    exit 1
fi

apt-get update

# Paquets obligatoires
apt-get install -y iproute2 nmap arp-scan tcpdump iw jq

# Paquets optionnels (échec non bloquant)
if ! apt-get install -y nbtscan avahi-utils; then
    echo "Installation des outils optionnels échouée, le script fonctionnera sans eux." >&2
fi

echo "Installation des dépendances terminée."
