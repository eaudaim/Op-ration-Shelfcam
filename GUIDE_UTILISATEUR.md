# Guide utilisateur et technique

Ce document décrit le fonctionnement détaillé du projet. Il combine un manuel d'utilisation et un guide technique pour faciliter le déploiement d'une reconnaissance réseau rapide (Phase 1) suivie d'une énumération ciblée (Phase 2).

## 1. Aperçu général

Le projet est conçu pour des déploiements sur Raspberry Pi lors d'opérations Red Team. Il automatise une phase de découverte silencieuse puis propose une phase d'analyse approfondie sur les cibles les plus prometteuses. Les scripts sont écrits en `bash` et dépendent d'outils standards (nmap, arp-scan, tcpdump, etc.).

### Workflow global
1. **Installation** des dépendances sur le Raspberry Pi.
2. **Phase 1** : découverte rapide du réseau et collecte d'informations de base.
3. **Analyse** optionnelle des résultats de Phase 1.
4. **Génération de configuration** pour la Phase 2 à partir des données de Phase 1.
5. **Phase 2** : énumération ciblée et collecte de bannières / services.
6. **Rapports** et synthèse des résultats.

## 2. Installation et prérequis

### 2.1 Dépendances nécessaires
- `ip`, `nmap`, `arp-scan`, `tcpdump`, `iw`, `jq`
- Outils optionnels : `nbtscan`, `avahi-browse`

### 2.2 Installation automatique
Un script automatise l'installation :
```bash
sudo ./install.sh
```
Le script utilise `apt-get`. Il doit être exécuté avec les privilèges root.

## 3. Configuration

### 3.1 Phase 1 – `config-phase1.json`
Ce fichier définit les options de reconnaissance initiale :
- `base_dir` : dossier où seront écrits les résultats.
- `global_timeout` : durée maximale globale (secondes).
- `adaptation` : seuils pour réduire automatiquement les délais sur les grands réseaux.
- `modules` : activation des modules (`arp_scan`, `nmap`, `mdns`, `netbios`, `tcpdump`, `ttl_fingerprint`, `reverse_dns`, `target_scoring`).
- `timeouts` : délais spécifiques à chaque module.

### 3.2 Phase 2 – `config-phase2.json`
La Phase 2 s'appuie sur un fichier généré depuis les résultats de Phase 1 :
```bash
./generate-phase2-config.sh <dossier_phase1>
```
Un fichier `config-phase2.json` est écrit dans le répertoire de Phase 1 et inclut :
- `phase1_results_path` : chemin vers les données de Phase 1.
- `strategy` : `intensive`, `selective` ou `minimal` (défini automatiquement par la Phase 1).
- `global_timeout`, `max_targets` : limites globales de temps et de nombre de cibles.
- `focus_areas` : modules à activer lors de la Phase 2 (bannières HTTP/SSH/FTP, SMB, SNMP, etc.).

## 4. Phase 1 – Découverte rapide

### 4.1 Lancement
```bash
sudo ./recon-phase1.sh
```
Le script détecte automatiquement l'interface Wi‑Fi si nécessaire et exécute en parallèle :
- `arp-scan` pour lister les hôtes,
- `nmap` pour la découverte et un scan rapide,
- `avahi-browse` (mDNS) et `nbtscan` (NetBIOS),
- `tcpdump` pour capturer le trafic,
- fingerprinting TTL et résolutions DNS inverses,
- scoring des cibles selon ports ouverts, OS présumé, etc.

### 4.2 Fichiers produits
Dans un sous-dossier horodaté du `base_dir` :
- `arp-scan.txt`, `nmap-live.txt`, `nmap-detailed.txt`
- `mdns.txt`, `netbios.txt`, `capture.pcap`
- `os-fingerprint.txt`, `reverse-dns.txt`, `port-summary.txt`
- `targets-scored.txt`, `phase1-intel.json`
- `recommended-phase2.txt` (stratégie suggérée pour Phase 2)
- `traffic-analysis.txt`
- `execution.log`, `error.log`

## 5. Outils d'analyse de Phase 1
Ces scripts s'exécutent sur le dossier de résultats créé par `recon-phase1.sh` :

- `./analyze-phase1.sh <dir>` : liste les cibles les mieux notées.
- `./intel-summary.sh <dir>` : produit une synthèse lisible de `phase1-intel.json`.
- `./target-prioritizer.sh <dir> [score_min]` : filtre et re‑score les cibles selon un seuil.

## 6. Phase 2 – Énumération ciblée

### 6.1 Préparation
Créer la configuration puis lancer la Phase 2 :
```bash
./generate-phase2-config.sh <dossier_phase1>
sudo ./recon-phase2.sh <dossier_phase1>/config-phase2.json
```
Le script limite à trois tâches parallèles pour rester discret et respecte la stratégie définie.

### 6.2 Modules et actions
Selon les ports ouverts et `focus_areas` :
- `nmap` : scan de version sur les ports détectés.
- `http_enum` : en-têtes et détection simple de CMS.
- `ssh_enum`, `ftp_enum`, `generic_banner` : capture de bannières.
- `smb_enum`, `snmp_enum` : énumération SMB et SNMP.
- `detect_monitoring` : recherche d'équipements de sécurité.
- `vulnerability_scanning` : indice de versions obsolètes ou mots de passe par défaut.

### 6.3 Fichiers produits
Dans `phase2-<timestamp>` situé dans le dossier Phase 1 :
- `nmap-<ip>.txt`, `http-<ip>-<port>.txt`, `ssh-<ip>-<port>.txt`, etc.
- `monitoring-check.txt`, `vulnerability-hints.txt`
- `final-report.txt` : rapport consolidé incluant un rappel des cibles Phase 1.
- `execution.log`, `error.log`

## 7. Bonnes pratiques et sécurité
- Exécuter les scripts **en root** pour permettre l'utilisation de `arp-scan`, `tcpdump`, etc.
- Les tâches respectent un `GLOBAL_TIMEOUT` pour éviter les scans interminables.
- Les captures `pcap` et rapports peuvent contenir des informations sensibles : protéger le dossier `base_dir`.
- L'utilisation sur un réseau sans autorisation explicite est illégale.

## 8. Architecture technique
Chaque script est autonome et vérifie la présence des binaires requis. Les opérations sont journalisées dans `execution.log` et les erreurs dans `error.log`. La Phase 1 construit également `phase1-intel.json` : un résumé JSON des hôtes avec ports, score et recommandations pouvant être exploité par d'autres outils.

## 9. Résumé des entrées / sorties
| Étape | Entrée principale | Commande | Sorties clés |
|------|------------------|----------|--------------|
| Installation | – | `sudo ./install.sh` | Outils système installés |
| Phase 1 | `config-phase1.json` | `sudo ./recon-phase1.sh` | Dossier horodaté avec résultats et `recommended-phase2.txt` |
| Analyse Phase 1 | Dossier Phase 1 | `./analyze-phase1.sh`, `./intel-summary.sh`, `./target-prioritizer.sh` | Rapports console |
| Génération config Phase 2 | Dossier Phase 1 | `./generate-phase2-config.sh` | `config-phase2.json` |
| Phase 2 | `config-phase2.json` | `sudo ./recon-phase2.sh config-phase2.json` | Dossier `phase2-<timestamp>` avec rapports détaillés |

Ce guide couvre l'essentiel pour exploiter le projet en production ou lors d'exercices Red Team. Pour des adaptations supplémentaires, examiner directement les scripts bash fournis.
