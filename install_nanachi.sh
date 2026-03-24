#!/bin/bash
###############################################################################
#                    SCRIPT D'INSTALLATION NANACHI.PY                         #
#         Détection automatique : Arch / Debian-Ubuntu / Fedora-RHEL          #
###############################################################################

set -e

# ── Couleurs ─────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║          🔥  INSTALLATION NANACHI PENTEST TOOL 🔥         ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Vérification root ─────────────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}❌ Ce script doit être exécuté en tant que root (sudo)${NC}"
    exit 1
fi

# Récupérer le vrai utilisateur (même sous sudo)
REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME=$(eval echo "~$REAL_USER")
NANACHI_DIR="$REAL_HOME/nanachi"

# ── Détection de l'OS ─────────────────────────────────────────────────────────
detect_os() {
    if command -v pacman &>/dev/null; then
        OS="arch"
        PKG_MANAGER="pacman"
    elif command -v apt &>/dev/null; then
        OS="debian"
        PKG_MANAGER="apt"
    elif command -v dnf &>/dev/null; then
        OS="fedora"
        PKG_MANAGER="dnf"
    elif command -v yum &>/dev/null; then
        OS="rhel"
        PKG_MANAGER="yum"
    else
        echo -e "${RED}❌ Gestionnaire de paquets non supporté${NC}"
        exit 1
    fi
}

detect_os

echo -e "${BLUE}🔍 OS détecté : ${OS} (${PKG_MANAGER})${NC}"
echo -e "${BLUE}👤 Utilisateur : ${REAL_USER} (home: ${REAL_HOME})${NC}"
echo ""

# ── Fonctions d'installation génériques ──────────────────────────────────────

pkg_update() {
    case "$OS" in
        arch)   pacman -Sy --noconfirm ;;
        debian) apt update ;;
        fedora|rhel) $PKG_MANAGER check-update || true ;;
    esac
}

pkg_install() {
    case "$OS" in
        arch)   pacman -S --noconfirm --needed "$@" ;;
        debian) apt install -y "$@" ;;
        fedora|rhel) $PKG_MANAGER install -y "$@" ;;
    esac
}

# Installation via yay (AUR — Arch uniquement)
aur_install() {
    if [ "$OS" != "arch" ]; then return; fi
    if command -v yay &>/dev/null; then
        sudo -u "$REAL_USER" yay -S --noconfirm --needed "$@"
    else
        echo -e "${YELLOW}⚠  yay non trouvé, skip AUR: $*${NC}"
    fi
}

# ── [1/9] Mise à jour des dépôts ─────────────────────────────────────────────
echo -e "${YELLOW}[1/9] Mise à jour des dépôts...${NC}"
pkg_update
echo -e "${GREEN}✓ Dépôts mis à jour${NC}"

# ── [2/9] Outils réseau ───────────────────────────────────────────────────────
echo -e "${YELLOW}[2/9] Installation des outils réseau...${NC}"

case "$OS" in
    arch)
        pkg_install \
            aircrack-ng \
            nmap \
            sqlmap \
            openbsd-netcat \
            iw \
            wireless_tools \
            networkmanager \
            hostapd \
            dnsmasq \
            net-tools \
            iproute2 \
            gobuster
        ;;
    debian)
        pkg_install \
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
            iproute2 \
            gobuster
        ;;
    fedora|rhel)
        pkg_install \
            aircrack-ng \
            nmap \
            sqlmap \
            nmap-ncat \
            iw \
            wireless-tools \
            NetworkManager \
            hostapd \
            dnsmasq \
            net-tools \
            iproute
        ;;
esac

echo -e "${GREEN}✓ Outils réseau installés${NC}"

# ── [3/9] Outils SSH ──────────────────────────────────────────────────────────
echo -e "${YELLOW}[3/9] Installation des outils SSH...${NC}"

case "$OS" in
    arch)   pkg_install sshpass openssh ;;
    debian) pkg_install sshpass openssh-client ;;
    fedora|rhel) pkg_install sshpass openssh-clients ;;
esac

echo -e "${GREEN}✓ Outils SSH installés${NC}"

# ── [4/9] LinPEAS ─────────────────────────────────────────────────────────────
echo -e "${YELLOW}[4/9] Installation de LinPEAS...${NC}"

LINPEAS_PATH="/usr/local/bin/linpeas.sh"

if [ "$OS" = "arch" ] && command -v yay &>/dev/null; then
    # Essayer peass-ng depuis l'AUR
    if sudo -u "$REAL_USER" yay -S --noconfirm --needed peass-ng 2>/dev/null; then
        # peass-ng installe dans /usr/share/peass/linpeas/linpeas.sh
        PEASS_LINPEAS="/usr/share/peass/linpeas/linpeas.sh"
        if [ -f "$PEASS_LINPEAS" ]; then
            ln -sf "$PEASS_LINPEAS" "$LINPEAS_PATH"
            echo -e "${GREEN}✓ LinPEAS installé via peass-ng (AUR) → $LINPEAS_PATH${NC}"
        fi
    else
        echo -e "${YELLOW}⚠  peass-ng AUR indisponible, téléchargement direct...${NC}"
    fi
fi

# Fallback curl si linpeas.sh pas encore là
if [ ! -f "$LINPEAS_PATH" ] || [ ! -s "$LINPEAS_PATH" ]; then
    curl -fsSL https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh \
        -o "$LINPEAS_PATH"
    chmod +x "$LINPEAS_PATH"
    echo -e "${GREEN}✓ LinPEAS téléchargé dans $LINPEAS_PATH${NC}"
else
    echo -e "${BLUE}ℹ  LinPEAS déjà installé${NC}"
fi

# ── [5/9] Base OUI → ~/nanachi/ ───────────────────────────────────────────────
echo -e "${YELLOW}[5/9] Téléchargement de la base OUI (fabricants MAC)...${NC}"

mkdir -p "$NANACHI_DIR"
OUI_PATH="$NANACHI_DIR/oui.txt"

if [ ! -f "$OUI_PATH" ]; then
    curl -fsSL https://standards-oui.ieee.org/oui/oui.txt -o "$OUI_PATH"
    chown "$REAL_USER:$REAL_USER" "$OUI_PATH"
    echo -e "${GREEN}✓ Base OUI téléchargée dans $OUI_PATH${NC}"
else
    echo -e "${BLUE}ℹ  Base OUI déjà présente dans $OUI_PATH${NC}"
fi

chown -R "$REAL_USER:$REAL_USER" "$NANACHI_DIR"

# ── [6/9] Python3 + pip ───────────────────────────────────────────────────────
echo -e "${YELLOW}[6/9] Installation de Python3 et pip...${NC}"

case "$OS" in
    arch)   pkg_install python python-pip python-setuptools ;;
    debian) pkg_install python3 python3-pip python3-dev python3-setuptools ;;
    fedora|rhel) pkg_install python3 python3-pip python3-devel python3-setuptools ;;
esac

echo -e "${GREEN}✓ Python3 installé${NC}"

# ── [7/9] Bibliothèques Python ────────────────────────────────────────────────
echo -e "${YELLOW}[7/9] Installation des bibliothèques Python...${NC}"

pip3 install --break-system-packages \
    rich \
    scapy \
    pyperclip \
    paramiko \
    requests \
    urllib3

echo -e "${GREEN}✓ Bibliothèques Python installées${NC}"

# ── [8/9] haiti + cool-retro-term ────────────────────────────────────────────
echo -e "${YELLOW}[8/9] Installation de haiti et cool-retro-term...${NC}"

# cool-retro-term
case "$OS" in
    arch)
        pkg_install cool-retro-term
        ;;
    debian)
        apt install -y cool-retro-term 2>/dev/null || \
            echo -e "${YELLOW}⚠  cool-retro-term non dispo via apt, installer manuellement${NC}"
        ;;
    fedora|rhel)
        $PKG_MANAGER install -y cool-retro-term 2>/dev/null || \
            echo -e "${YELLOW}⚠  cool-retro-term non dispo, installer manuellement${NC}"
        ;;
esac

# haiti — via gem (Ruby) sur tous les OS
if ! command -v ruby &>/dev/null; then
    case "$OS" in
        arch)   pkg_install ruby ;;
        debian) pkg_install ruby ruby-dev ;;
        fedora|rhel) pkg_install ruby ruby-devel ;;
    esac
fi

# Installer haiti en tant que l'utilisateur réel (gem user install)
echo -e "${BLUE}  → Installation de haiti-hash via gem (user: $REAL_USER)...${NC}"
sudo -u "$REAL_USER" gem install haiti-hash

# Détecter le path gem de l'user et l'ajouter au PATH dans son shell
HAITI_BIN_DIR=$(sudo -u "$REAL_USER" bash -c \
    'gem environment gemdir 2>/dev/null || echo ""')

if [ -n "$HAITI_BIN_DIR" ]; then
    HAITI_BIN="$HAITI_BIN_DIR/bin"
    
    # Créer un symlink system pour que sudo puisse aussi trouver haiti
    HAITI_EXEC=$(find "$REAL_HOME/.local/share/gem" "$REAL_HOME/.gem" \
        -name haiti -type f -executable 2>/dev/null | head -1)
    
    if [ -n "$HAITI_EXEC" ]; then
        ln -sf "$HAITI_EXEC" /usr/local/bin/haiti
        echo -e "${GREEN}✓ haiti installé → symlink /usr/local/bin/haiti → $HAITI_EXEC${NC}"
    fi
fi

# Ajouter gem bin au PATH dans ~/.bashrc et ~/.zshrc si pas déjà présent
for RC_FILE in "$REAL_HOME/.bashrc" "$REAL_HOME/.zshrc"; do
    if [ -f "$RC_FILE" ]; then
        if ! grep -q 'gem/ruby' "$RC_FILE" 2>/dev/null; then
            cat >> "$RC_FILE" << 'RCEOF'

# Haiti / gem path (ajouté par install_nanachi.sh)
if command -v ruby &>/dev/null; then
    GEM_BIN="$(ruby -e 'puts Gem.user_dir' 2>/dev/null)/bin"
    [[ -d "$GEM_BIN" ]] && export PATH="$GEM_BIN:$PATH"
fi
RCEOF
            chown "$REAL_USER:$REAL_USER" "$RC_FILE"
            echo -e "${GREEN}✓ PATH gem ajouté dans $RC_FILE${NC}"
        fi
    fi
done

echo -e "${GREEN}✓ haiti + cool-retro-term installés${NC}"

# ── [9/9] Permissions sudoers ─────────────────────────────────────────────────
echo -e "${YELLOW}[9/9] Configuration des permissions sudoers...${NC}"

SUDOERS_FILE="/etc/sudoers.d/nanachi"

# Sur Arch le groupe sudoers s'appelle "wheel", sur Debian "sudo"
case "$OS" in
    arch)   SUDO_GROUP="wheel" ;;
    *)      SUDO_GROUP="sudo" ;;
esac

cat > "$SUDOERS_FILE" << SUDOEOF
# Permissions pour nanachi.py
%${SUDO_GROUP} ALL=(ALL) NOPASSWD: /usr/bin/nmap
%${SUDO_GROUP} ALL=(ALL) NOPASSWD: /usr/sbin/airmon-ng
%${SUDO_GROUP} ALL=(ALL) NOPASSWD: /usr/sbin/airodump-ng
%${SUDO_GROUP} ALL=(ALL) NOPASSWD: /usr/sbin/aireplay-ng
%${SUDO_GROUP} ALL=(ALL) NOPASSWD: /usr/bin/nmcli
%${SUDO_GROUP} ALL=(ALL) NOPASSWD: /usr/sbin/iw
%${SUDO_GROUP} ALL=(ALL) NOPASSWD: /usr/bin/pkill
%${SUDO_GROUP} ALL=(ALL) NOPASSWD: /usr/sbin/ip
%${SUDO_GROUP} ALL=(ALL) NOPASSWD: /usr/bin/hostapd
%${SUDO_GROUP} ALL=(ALL) NOPASSWD: /usr/sbin/dnsmasq
%${SUDO_GROUP} ALL=(ALL) NOPASSWD: /usr/sbin/sysctl
%${SUDO_GROUP} ALL=(ALL) NOPASSWD: /usr/bin/rfkill
%${SUDO_GROUP} ALL=(ALL) NOPASSWD: /usr/local/bin/linpeas.sh
SUDOEOF

chmod 0440 "$SUDOERS_FILE"
visudo -c -f "$SUDOERS_FILE" && \
    echo -e "${GREEN}✓ sudoers validé (groupe: ${SUDO_GROUP})${NC}" || \
    { echo -e "${RED}❌ Erreur sudoers, fichier supprimé${NC}"; rm "$SUDOERS_FILE"; }

# Rendre nanachi.py exécutable si présent
if [ -f "./nanachi.py" ]; then
    chmod +x ./nanachi.py
    chown "$REAL_USER:$REAL_USER" ./nanachi.py
    echo -e "${GREEN}✓ nanachi.py rendu exécutable${NC}"
fi

# ── Résumé ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║              ✅  INSTALLATION TERMINÉE !  ✅               ║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}📦 Outils installés :${NC}"
echo -e "  ✓ aircrack-ng (airmon-ng, airodump-ng, aireplay-ng)"
echo -e "  ✓ nmap / sqlmap / gobuster"
echo -e "  ✓ netcat / sshpass"
echo -e "  ✓ hostapd / dnsmasq"
echo -e "  ✓ LinPEAS  →  $LINPEAS_PATH"
echo -e "  ✓ Base OUI →  $OUI_PATH"
echo -e "  ✓ haiti    →  /usr/local/bin/haiti"
echo -e "  ✓ cool-retro-term"
echo ""
echo -e "${GREEN}🐍 Bibliothèques Python :${NC}"
echo -e "  ✓ rich · scapy · paramiko · pyperclip · requests"
echo ""
echo -e "${YELLOW}⚠  IMPORTANT :${NC}"
echo -e "  • Rechargez votre shell pour que le PATH gem soit actif :"
echo -e "    ${CYAN}source ~/.bashrc${NC}  ou  ${CYAN}source ~/.zshrc${NC}"
echo -e "  • Vérifiez haiti : ${CYAN}haiti --version${NC}"
echo -e "  • Vos wordlists/rules doivent être dans : ${CYAN}${NANACHI_DIR}/${NC}"
echo ""
echo -e "${BLUE}🚀 Pour lancer nanachi :${NC}"
echo -e "  ${CYAN}sudo python3 nanachi.py${NC}"
echo ""
echo -e "${GREEN}Bon pentest ! 🔥💀${NC}"