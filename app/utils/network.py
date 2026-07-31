import socket
import ipaddress
from urllib.parse import urlparse

# Private and reserved IP ranges (IPv4 and IPv6)
PRIVATE_IP_RANGES = [
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fc00::/7'),
    ipaddress.ip_network('fe80::/10'),
]

def is_safe_url(url):
    """
    Check if a URL is safe to fetch (Prevents SSRF).
    """
    try:
        parsed = urlparse(url)
        if not parsed.scheme or parsed.scheme not in ['http', 'https']:
            return False
        
        hostname = parsed.hostname
        if not hostname:
            return False
            
        # Resolve hostname to IP
        ip = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(ip)
        
        for range in PRIVATE_IP_RANGES:
            if ip_obj in range:
                return False
                
        return True
    except Exception:
        return False
