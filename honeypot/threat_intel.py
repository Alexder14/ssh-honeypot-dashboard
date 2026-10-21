import urllib.request
import json
import logging

# Cache en memoria para no saturar la API publica
_GEO_CACHE = {}

def get_ip_intel(ip: str) -> dict:
    """
    Obtiene informacion geografica y del proveedor de servicios (ISP) de una IP.
    Maneja IPs locales/privadas y guarda en cache los resultados para optimizar.
    """
    # Manejo de IPs locales o de loopback para pruebas
    if ip in ("127.0.0.1", "localhost", "0.0.0.0") or ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
        return {
            "country": "Local Network (Lab)",
            "city": "Test Lab",
            "lat": 19.4326,   # Coordenada representativa para pruebas en el mapa
            "lon": -99.1332,
            "isp": "Private RFC1918 / Internal"
        }

    if ip in _GEO_CACHE:
        return _GEO_CACHE[ip]

    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,city,lat,lon,isp"
        req = urllib.request.Request(url, headers={"User-Agent": "ShadowSSH-Honeypot/1.0"})
        with urllib.request.urlopen(req, timeout=3) as response:
            data = json.loads(response.read().decode())
            if data.get("status") == "success":
                intel = {
                    "country": data.get("country", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "lat": float(data.get("lat", 0.0)),
                    "lon": float(data.get("lon", 0.0)),
                    "isp": data.get("isp", "Unknown")
                }
                _GEO_CACHE[ip] = intel
                return intel
    except Exception as e:
        logging.warning(f"Error resolviendo GeoIP para {ip}: {e}")

    # Fallback si la API no responde o hay error de red
    fallback = {
        "country": "Unknown",
        "city": "Unknown",
        "lat": 0.0,
        "lon": 0.0,
        "isp": "Unknown"
    }
    _GEO_CACHE[ip] = fallback
    return fallback
