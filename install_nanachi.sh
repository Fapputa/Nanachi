#!/bin/bash
###############################################################################
#                    SCRIPT D'INSTALLATION NANACHI.PY                         #
#                   Installe tous les outils nécessaires                      #
###############################################################################

set -e  # Arrêter en cas d'erreur

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║          🔥  INSTALLATION NANACHI PENTEST TOOL 🔥         ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Vérifier si on est root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}❌ Ce script doit être exécuté en tant que root (sudo)${NC}"
    exit 1
fi

echo -e "${YELLOW}[1/8] Mise à jour des dépôts APT...${NC}"
apt update

echo -e "${YELLOW}[2/8] Installation des outils réseau...${NC}"
apt install -y \
    aircrack-ng \
    nmap \
    sqlmap \
    netcat-openbsd \
    iw \
    wireless-tools \
    network-manager \
    hostapd \
    dnsmasq \
    net-tools \
    iproute2

echo -e "${GREEN}✓ Outils réseau installés${NC}"

echo -e "${YELLOW}[3/8] Installation des outils SSH...${NC}"
apt install -y \
    sshpass \
    openssh-client

echo -e "${GREEN}✓ Outils SSH installés${NC}"

echo -e "${YELLOW}[4/8] Téléchargement de LinPEAS...${NC}"
LINPEAS_PATH="/usr/local/bin/linpeas.sh"
if [ ! -f "$LINPEAS_PATH" ]; then
    curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -o "$LINPEAS_PATH"
    chmod +x "$LINPEAS_PATH"
    # Créer aussi une copie locale
    cp "$LINPEAS_PATH" ./linpeas.sh 2>/dev/null || true
    echo -e "${GREEN}✓ LinPEAS téléchargé dans $LINPEAS_PATH${NC}"
else
    echo -e "${BLUE}ℹ LinPEAS déjà installé${NC}"
fi

echo -e "${YELLOW}[5/8] Téléchargement de la base de données OUI (fabricants MAC)...${NC}"
OUI_PATH="./oui.txt"
if [ ! -f "$OUI_PATH" ]; then
    curl -L https://standards-oui.ieee.org/oui/oui.txt -o "$OUI_PATH"
    echo -e "${GREEN}✓ Base OUI téléchargée${NC}"
else
    echo -e "${BLUE}ℹ Base OUI déjà présente${NC}"
fi

echo -e "${YELLOW}[6/8] Installation de Python3 et pip...${NC}"
apt install -y \
    python3 \
    python3-pip \
    python3-dev \
    python3-setuptools

echo -e "${GREEN}✓ Python3 installé${NC}"

echo -e "${YELLOW}[7/8] Installation des bibliothèques Python...${NC}"
pip3 install --break-system-packages \
    rich \
    scapy \
    pyperclip \
    paramiko \
    requests \
    urllib3

echo -e "${GREEN}✓ Bibliothèques Python installées${NC}"

echo -e "${YELLOW}[8/8] Configuration des permissions...${NC}"

# Permettre à l'utilisateur d'exécuter certaines commandes sans mot de passe
SUDOERS_FILE="/etc/sudoers.d/nanachi"
cat > "$SUDOERS_FILE" << 'EOF'
# Permissions pour nanachi.py
%sudo ALL=(ALL) NOPASSWD: /usr/bin/nmap
%sudo ALL=(ALL) NOPASSWD: /usr/sbin/airmon-ng
%sudo ALL=(ALL) NOPASSWD: /usr/sbin/airodump-ng
%sudo ALL=(ALL) NOPASSWD: /usr/sbin/aireplay-ng
%sudo ALL=(ALL) NOPASSWD: /usr/bin/nmcli
%sudo ALL=(ALL) NOPASSWD: /usr/sbin/iw
%sudo ALL=(ALL) NOPASSWD: /usr/bin/pkill
%sudo ALL=(ALL) NOPASSWD: /usr/sbin/ip
%sudo ALL=(ALL) NOPASSWD: /usr/bin/hostapd
%sudo ALL=(ALL) NOPASSWD: /usr/sbin/dnsmasq
%sudo ALL=(ALL) NOPASSWD: /usr/sbin/sysctl
%sudo ALL=(ALL) NOPASSWD: /usr/bin/rfkill
EOF
chmod 0440 "$SUDOERS_FILE"

echo -e "${GREEN}✓ Permissions configurées${NC}"

# Vérifier que nanachi.py existe
if [ -f "./nanachi.py" ]; then
    chmod +x ./nanachi.py
    echo -e "${GREEN}✓ nanachi.py rendu exécutable${NC}"
fi

echo ""
echo -e "${CYAN}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║              ✅  INSTALLATION TERMINÉE !  ✅               ║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}📦 Outils installés :${NC}"
echo -e "  ✓ aircrack-ng (airmon-ng, airodump-ng, aireplay-ng)"
echo -e "  ✓ nmap"
echo -e "  ✓ sqlmap"
echo -e "  ✓ netcat"
echo -e "  ✓ hostapd (Fake AP)"
echo -e "  ✓ dnsmasq (serveur DHCP/DNS)"
echo -e "  ✓ LinPEAS"
echo -e "  ✓ Base de données OUI (fabricants MAC)"
echo ""
echo -e "${GREEN}🐍 Bibliothèques Python :${NC}"
echo -e "  ✓ rich (interface)"
echo -e "  ✓ scapy (capture de paquets)"
echo -e "  ✓ paramiko (SSH)"
echo -e "  ✓ pyperclip (presse-papier)"
echo ""
echo -e "${YELLOW}⚠  IMPORTANT :${NC}"
echo -e "  • Redémarrez votre session pour que les permissions sudo prennent effet"
echo -e "  • Ou exécutez : ${CYAN}newgrp sudo${NC}"
echo ""
echo -e "${BLUE}🚀 Pour lancer nanachi :${NC}"
echo -e "  ${CYAN}sudo python3 nanachi.py${NC}"
echo -e "  ${CYAN}# OU${NC}"
echo -e "  ${CYAN}sudo ./nanachi.py${NC} ${YELLOW}(si exécutable)${NC}"
echo ""
echo -e "${GREEN}Bon pentest ! 🔥💀${NC}"