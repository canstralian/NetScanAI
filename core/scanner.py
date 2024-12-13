import socket
import asyncio
import ipaddress
from typing import List, Dict
import logging

async def validate_target(target: str) -> bool:
    """Validate if the target is a valid IP address or hostname."""
    try:
        # Try parsing as IP address
        ipaddress.ip_address(target)
        return True
    except ValueError:
        # Check if it's a valid hostname
        if len(target) > 255:
            return False
        allowed = set("-." + "abcdefghijklmnopqrstuvwxyz0123456789")
        return all(c.lower() in allowed for c in target)

async def scan_port(target: str, port: int) -> Dict:
    """Scan a single port."""
    try:
        # Use a shorter timeout for faster scans
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        
        # Common ports and their services
        common_ports = {
            20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet",
            25: "smtp", 53: "dns", 80: "http", 110: "pop3",
            143: "imap", 443: "https", 465: "smtps", 587: "submission",
            993: "imaps", 995: "pop3s", 3306: "mysql", 5432: "postgresql",
            8080: "http-alt", 8443: "https-alt", 27017: "mongodb"
        }
        
        result = sock.connect_ex((target, port))
        sock.close()
        
        service = "unknown"
        if result == 0:
            try:
                service = socket.getservbyport(port)
            except (OSError, socket.error):
                service = common_ports.get(port, "unknown")
                
            # Try to get additional info for HTTP/HTTPS ports
            if service in ["http", "https", "http-alt", "https-alt"]:
                try:
                    protocol = "https" if service in ["https", "https-alt"] else "http"
                    with socket.create_connection((target, port), timeout=1) as s:
                        s.send(f"HEAD / HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
                        response = s.recv(1024).decode()
                        if "Server:" in response:
                            server = response.split("Server:", 1)[1].split("\r\n")[0].strip()
                            service = f"{service} ({server})"
                except:
                    pass
        
        return {
            "port": port,
            "state": "open" if result == 0 else "closed",
            "service": service
        }
    except Exception as e:
        logging.error(f"Error scanning port {port}: {str(e)}")
        return {"port": port, "state": "error", "service": "unknown"}

async def scan_target(target: str, port_range: str = "1-1024") -> List[Dict]:
    """Scan a target for open ports."""
    if not await validate_target(target):
        raise ValueError("Invalid target specified")
    
    try:
        start_port, end_port = map(int, port_range.split('-'))
        if not (0 <= start_port <= 65535 and 0 <= end_port <= 65535):
            raise ValueError("Port range must be between 0-65535")
    except ValueError:
        raise ValueError("Invalid port range format")

    tasks = []
    for port in range(start_port, end_port + 1):
        tasks.append(scan_port(target, port))
    
    results = await asyncio.gather(*tasks)
    # Return all results, sorted by port number
    return sorted([r for r in results], key=lambda x: x["port"])
