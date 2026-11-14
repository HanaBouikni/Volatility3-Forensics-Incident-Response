#!/bin/bash
# 02_volatility_setup.sh — Installation de Volatility 3 + génération du Symbol Table (ISF)
set -e

# Installation dans un environnement virtuel Python
python3 -m venv ~/volatility-env
source ~/volatility-env/bin/activate
pip install volatility3

# Génération du Symbol Table (ISF) à partir des symboles de debug du noyau
sudo apt install linux-image-$(uname -r)-dbgsym -y
git clone https://github.com/volatilityfoundation/dwarf2json
cd dwarf2json && go build

sudo ./dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-$(uname -r) \
    > ~/linux-$(uname -r).json

# Copier le JSON dans le dossier des symboles Volatility
cp ~/linux-$(uname -r).json \
   ~/volatility-env/lib/python3.12/site-packages/volatility3/framework/symbols/linux/

echo "[+] Volatility 3 prêt. Exemple d'analyse :"
echo "    vol -f /tmp/memory.lime linux.pslist"
