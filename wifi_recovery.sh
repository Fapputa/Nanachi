#!/bin/bash
# Script de récupération d'urgence pour restaurer le WiFi
# Usage: sudo ./wifi_recovery.sh [interface]
set -e
iface="${1:-wlp0s20f0u3}"
echo "╔════════════════════════════════════════════════════════╗"
echo "║     SCRIPT DE RÉCUPÉRATION WiFi D'URGENCE             ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""
echo "[1/8] Arrêt de tous les processus réseau..."
sudo pkill -9 -f airodump-ng 2>/dev/null || true
sudo pkill -9 -f aireplay-ng 2>/dev/null || true
sudo pkill -9 -f wpa_supplicant 2>/dev/null || true
sudo pkill -9 -f dhclient 2>/dev/null || true
sleep 2
echo "[2/8] Arrêt de NetworkManager..."
sudo systemctl stop NetworkManager
sleep 2
echo "[3/8] Désactivation de l'interface $iface..."
sudo ip link set $iface down
sleep 2
echo "[4/8] Suppression de la configuration rfkill..."
sudo rfkill unblock wifi 2>/dev/null || true
sleep 1
echo "[5/8] Passage en mode managed..."
sudo iw $iface set type managed
sleep 2
echo "[6/8] Réactivation de l'interface..."
sudo ip link set $iface up
sleep 2
echo "[7/8] Redémarrage de NetworkManager..."
sudo systemctl restart NetworkManager
sleep 3
echo "[8/8] Tentative de reconnexion..."
nmcli device connect $iface 2>/dev/null || true
sleep 2
echo ""
echo "═══════════════════════════════════════════════════════"
echo "Vérification de l'état de l'interface:"
echo "═══════════════════════════════════════════════════════"
iwconfig $iface 2>/dev/null || echo "Erreur: impossible d'obtenir les infos iwconfig"
echo ""
ip link show $iface 2>/dev/null || echo "Erreur: impossible d'obtenir les infos ip link"
echo ""
nmcli device status | grep $iface || echo "Erreur: interface non trouvée dans nmcli"
echo ""
# Vérifier si on est en mode managed
if iwconfig $iface 2>/dev/null | grep -q "Mode:Managed\|Mode:Auto"; then
    echo "✓ SUCCESS: Interface $iface est maintenant en mode Managed"
    echo ""
    echo "Si le WiFi ne se connecte pas automatiquement, essayez:"
    echo "  nmcli device wifi list"
    echo "  nmcli device wifi connect <SSID> password <mot_de_passe>"
else
    echo "✗ ÉCHEC: L'interface n'est pas en mode Managed"
    echo ""
    echo "Actions manuelles recommandées:"
    echo "  1. Redémarrer le système: sudo reboot"
    echo "  2. Ou réinitialiser le module WiFi:"
    echo "     sudo modprobe -r $(lspci -k | grep -A 3 'Network controller' | grep 'Kernel driver' | awk '{print $5}')"
    echo "     sudo modprobe $(lspci -k | grep -A 3 'Network controller' | grep 'Kernel driver' | awk '{print $5}')"
fi
echo ""
echo "═══════════════════════════════════════════════════════"
