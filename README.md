# 🍯 Honeypot SSH avec confinement AppArmor/Seccomp et monitoring ELK

Ce projet a été réalisé dans le cadre du module "Développement d’Applications Sécurisées" (Filière GDNC - ENSAF / USMBA). Il consiste à déployer un honeypot SSH interactif en Python, sécurisé par des mécanismes du noyau Linux, et supervisé en temps réel par la stack Elastic.

## 🎯 Objectifs et Architecture

* **Honeypot SSH (`paramiko`)** : Simulation d'un serveur SSH enregistrant les tentatives d'authentification et les commandes tapées au format JSON.
* **Confinement Haute Sécurité** :
  * **AppArmor** : Profil strict autorisant uniquement l'accès aux fichiers du honeypot et interdisant la lecture de chemins sensibles (`/etc/**`).
  * **Seccomp (`pyseccomp`)** : Filtrage des appels système avec une liste noire bloquant la création de processus (`execve`, `fork`), la manipulation de modules et le montage (`mount`).
* **Supervision ELK & Détection Brute-Force** :
  * Parsing des logs JSONL via Logstash.
  * Filtre Logstash `aggregate` permettant la détection d'attaques brute-force (seuil > 5 tentatives / minute par IP).
  * Indexation dans Elasticsearch et visualisation des alertes sur Kibana.

## 📁 Structure du dépôt

* `src/` : Code source Python du Honeypot (`ssh_honeypot.py`).
* `policy/` : Profil AppArmor (`honeypot-ssh`).
* `logstash/` : Fichiers de configuration du pipeline Logstash (`honeypot-ssh.conf`).

## ⚙️ Prérequis et Lancement

Le projet nécessite un environnement virtuel Python avec `paramiko` et `pyseccomp`.
Le honeypot est conçu pour être exécuté sous la protection d'AppArmor :
```bash
sudo aa-exec -p honeypot-ssh -- ./venv/bin/python ssh_honeypot.py --port 2222
