#!/bin/bash
# 01_lime_dump.sh — Capture de la mémoire RAM avec LiME (Linux Memory Extractor)
# Contexte : environnement VMware (et non VirtualBox/VBoxManage).
set -e

# Installation des dépendances et compilation de LiME
sudo apt install linux-headers-$(uname -r) build-essential git -y
git clone https://github.com/504ensicsLabs/LiME
cd LiME/src
make

# Génération du dump mémoire (format lime)
sudo insmod lime-$(uname -r).ko "path=/tmp/memory.lime format=lime"
ls -lh /tmp/memory.lime
# Résultat attendu : /tmp/memory.lime ~ 8,0 Go (RAM totale de la VM)
