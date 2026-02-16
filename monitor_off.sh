#!/bin/bash
set -x

# Utiliser le paramètre ou wlo1 par défaut
iface="${1:-wlo1}"

echo "[*] arrêt des processus utilisant l'interface..."
sudo pkill -f airodump-ng
sudo pkill -f aireplay-ng
sudo pkill -f wpa_supplicant

echo "[*] mise hors ligne de l'interface $iface..."
sudo ip link set $iface down
sleep 1

echo "[*] passage en mode managed..."
sudo iw $iface set type managed
sleep 1

echo "[*] réactivation de l'interface..."
sudo ip link set $iface up
sleep 1

echo "[*] relance de NetworkManager..."
sudo systemctl start NetworkManager
sleep 2

echo "[*] tentative de reconnexion automatique..."
nmcli device connect $iface

echo "[*] vérification..."
iwconfig $iface

echo "[*] statut de l'interface:"
ip link show $iface

echo "[*] restauration terminée!"