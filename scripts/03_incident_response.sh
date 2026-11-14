#!/bin/bash
# 03_incident_response.sh — Simulation d'attaque SSH + détection + isolement + capture
# VM de test UNIQUEMENT. Ne jamais lancer sur un système de production.

### 1) Simulation de l'attaque par force brute SSH (Hydra) ---------------------
sudo systemctl enable ssh
sudo systemctl start ssh

cat > /tmp/passwords.txt << 'EOF'
123456
password
root
admin
toor
hana
azerty
qwerty
ubuntu
123456789
EOF

hydra -l root -P /tmp/passwords.txt ssh://127.0.0.1 -t 4 -v

### 2) Détection de l'attaque dans les logs -----------------------------------
sudo journalctl -u ssh | grep -i "failed\|invalid\|disconnect"

### 3) Isolement immédiat du système ------------------------------------------
sudo iptables -P INPUT DROP
sudo iptables -P OUTPUT DROP
sudo iptables -L

### 4) Capture forensique des logs --------------------------------------------
sudo tar czf ~/logs-$(date +%Y%m%d).tgz /var/log/
ls -lh ~/logs-*.tgz
