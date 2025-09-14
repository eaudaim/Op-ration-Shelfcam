# Op-ration-Shelfcam

Outil modulaire de reconnaissance réseau en deux phases conçu pour les déploiements rapides sur Raspberry Pi. La Phase 1 réalise une découverte discrète en moins de trois minutes, tandis que la Phase 2 exploite ces résultats pour une énumération ciblée lors d'une visite ultérieure.

## Installation des dépendances

Un script d'installation (`install.sh`) installe automatiquement les outils requis. Exécutez-le une seule fois en tant que superutilisateur :

```bash
sudo ./install.sh
```

## Pré‑requis

Les scripts s'appuient sur les binaires suivants :

- `ip`, `nmap`, `arp-scan`, `tcpdump`, `iw`, `jq`
- Outils optionnels : `nbtscan`, `avahi-browse`

## Phase 1 – Découverte rapide

Configuration : `config-phase1.json` (base_dir par défaut : `/home/raspi3/recon`).

Exécution :

```bash
sudo ./recon-phase1.sh
```

Le script lance en parallèle ARP, mDNS, NetBIOS et une capture passive, puis effectue un fingerprinting TTL, des résolutions DNS inversées et un scoring automatique des cibles. Les principaux fichiers produits sont :

- `arp-scan.txt`, `nmap-live.txt`, `capture.pcap`
- `os-fingerprint.txt`, `reverse-dns.txt`, `targets-scored.txt`
- `phase1-intel.json`, `recommended-phase2.txt`, `traffic-analysis.txt`

## Phase 2 – Reconnaissance ciblée

Générez la configuration via `generate-phase2-config.sh` en pointant vers le dossier de résultats de la Phase 1 :

```bash
./generate-phase2-config.sh /chemin/vers/resultats-phase1 > config-phase2.json
sudo ./recon-phase2.sh config-phase2.json
```

Le script adapte automatiquement sa stratégie (`intensive`, `selective` ou `minimal`) selon les cibles prioritaires. Il collecte des bannières HTTP/HTTPS, SSH et FTP, détecte la surveillance réseau, génère des indices de vulnérabilités et écrit un rapport consolidé dans `final-report.txt`.

## Outils complémentaires

- `analyze-phase1.sh` : analyse hors‑ligne de la capture et statistiques de trafic.
- `intel-summary.sh` : synthèse lisible des deux phases.
- `target-prioritizer.sh` : re‑scoring manuel des cibles.
- `generate-phase2-config.sh` : aide à la création du fichier de configuration de la Phase 2.

## Structure du dépôt

- `recon-phase1.sh`, `recon-phase2.sh`
- `config-phase1.json`
- `analyze-phase1.sh`, `intel-summary.sh`, `target-prioritizer.sh`, `generate-phase2-config.sh`
- `install.sh`, `README.md`

## Avertissement

Ce projet est destiné à des exercices Red Team ou à des tests de sécurité autorisés. L'utilisation sur un réseau sans consentement explicite peut être illégale.

