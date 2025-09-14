# Op-ration-Shelfcam

Script de reconnaissance réseau automatique conçu pour être exécuté sur un Raspberry Pi. Il détecte l'interface Wi-Fi active, collecte les informations réseau et lance divers scans pour inventorier les hôtes et services présents sur le réseau cible.

## Installation des dépendances

Un script d'installation (`install.sh`) permet d'installer automatiquement tous les outils requis. Exécutez-le une fois en tant que superutilisateur :

```bash
sudo ./install.sh
```

## Pré-requis

Le script repose sur plusieurs outils système. Les binaires suivants doivent être présents :

- `ip`, `nmap`, `arp-scan`, `tcpdump`, `iw`, `jq`
- Outils optionnels : `nbtscan`, `avahi-browse`

## Configuration

Les paramètres principaux sont définis dans `config.json` :

- `interface` : interface réseau à utiliser (détection automatique si vide)
- `base_dir` : dossier où seront stockés les résultats
- `enable_mdns`, `enable_netbios`, `enable_tcpdump` : activation des modules facultatifs
- `timeouts` : délais d'exécution pour chaque module

## Utilisation

Exécutez le script en tant que superutilisateur :

```bash
sudo ./recon.sh
```

Les résultats et journaux sont enregistrés dans un dossier horodaté situé dans `base_dir`. Un fichier `resume.txt` résume les paramètres et le nombre d'hôtes détectés.

## Structure du dépôt

- `recon.sh` : script principal de reconnaissance
- `config.json` : fichier de configuration
- `install.sh` : installation des dépendances
- `README.md` : ce document

## Avertissement

Ce projet est destiné à des exercices Red Team ou à des tests de sécurité autorisés. L'utilisation sur un réseau sans consentement explicite peut être illégale.

