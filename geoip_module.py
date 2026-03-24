#!/usr/bin/env python3
"""
Module de géolocalisation IP pour nanachi.py
À ajouter au début du fichier après les imports
"""

import requests
import json
from typing import Optional, Dict

class GeoIPLookup:
    """Géolocalisation d'adresses IP publiques"""
    
    # Cache pour éviter les appels répétés
    _cache = {}
    
    @classmethod
    def lookup(cls, ip: str) -> Optional[Dict]:
        """
        Recherche la géolocalisation d'une IP
        Retourne: {
            'country': str,
            'country_code': str,
            'region': str,
            'city': str,
            'lat': float,
            'lon': float,
            'isp': str,
            'org': str,
            'as': str
        }
        """
        # Vérifier le cache
        if ip in cls._cache:
            return cls._cache[ip]
        
        # IPs privées ne sont pas géolocalisables
        if cls._is_private_ip(ip):
            return None
        
        try:
            # Utiliser ip-api.com (gratuit, pas de clé requise, 45 req/min)
            url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,lat,lon,isp,org,as"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('status') == 'success':
                    result = {
                        'country': data.get('country', 'Inconnu'),
                        'country_code': data.get('countryCode', ''),
                        'region': data.get('regionName', ''),
                        'city': data.get('city', ''),
                        'lat': data.get('lat'),
                        'lon': data.get('lon'),
                        'isp': data.get('isp', ''),
                        'org': data.get('org', ''),
                        'as': data.get('as', '')
                    }
                    
                    # Mettre en cache
                    cls._cache[ip] = result
                    return result
                else:
                    # Erreur API (probablement IP privée ou invalide)
                    return None
        
        except requests.RequestException as e:
            # Erreur réseau, retourner None silencieusement
            pass
        except Exception as e:
            # Autre erreur
            pass
        
        return None
    
    @classmethod
    def _is_private_ip(cls, ip: str) -> bool:
        """Vérifie si une IP est privée"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return True  # Format invalide
            
            first = int(parts[0])
            second = int(parts[1])
            
            # 10.0.0.0/8
            if first == 10:
                return True
            
            # 172.16.0.0/12
            if first == 172 and 16 <= second <= 31:
                return True
            
            # 192.168.0.0/16
            if first == 192 and second == 168:
                return True
            
            # 127.0.0.0/8 (loopback)
            if first == 127:
                return True
            
            # 169.254.0.0/16 (link-local)
            if first == 169 and second == 254:
                return True
            
            return False
        
        except:
            return True  # En cas d'erreur, considérer comme privée
    
    @classmethod
    def format_location(cls, geo_data: Optional[Dict]) -> str:
        """Formate les données de géolocalisation en une chaîne lisible"""
        if not geo_data:
            return "Non localisable (IP privée ou erreur)"
        
        parts = []
        
        if geo_data.get('city'):
            parts.append(geo_data['city'])
        
        if geo_data.get('region'):
            parts.append(geo_data['region'])
        
        if geo_data.get('country'):
            country = geo_data['country']
            if geo_data.get('country_code'):
                country = f"{country} ({geo_data['country_code']})"
            parts.append(country)
        
        location = ", ".join(parts) if parts else "Inconnu"
        
        # Ajouter coordonnées si disponibles
        if geo_data.get('lat') and geo_data.get('lon'):
            location += f" [{geo_data['lat']:.4f}, {geo_data['lon']:.4f}]"
        
        return location
    
    @classmethod
    def format_isp(cls, geo_data: Optional[Dict]) -> str:
        """Formate les informations ISP"""
        if not geo_data:
            return "N/A"
        
        # Préférer org, puis isp, puis as
        if geo_data.get('org'):
            return geo_data['org']
        elif geo_data.get('isp'):
            return geo_data['isp']
        elif geo_data.get('as'):
            return geo_data['as']
        
        return "N/A"


# ═══════════════════════════════════════════════════════════════════════════
# EXEMPLE D'UTILISATION
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    # Test avec une IP publique
    test_ips = [
        "8.8.8.8",           # Google DNS
        "1.1.1.1",           # Cloudflare
        "192.168.1.1",       # IP privée
        "92.184.106.121",    # Ton exemple
    ]
    
    for ip in test_ips:
        print(f"\n{'='*60}")
        print(f"IP: {ip}")
        print(f"{'='*60}")
        
        geo = GeoIPLookup.lookup(ip)
        
        if geo:
            print(f"Localisation: {GeoIPLookup.format_location(geo)}")
            print(f"ISP/Org:      {GeoIPLookup.format_isp(geo)}")
            print(f"\nDétails:")
            for key, value in geo.items():
                print(f"  {key:15}: {value}")
        else:
            print("Pas de données de géolocalisation disponibles")
