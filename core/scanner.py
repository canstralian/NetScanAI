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
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        sock.close()
        
        return {
            "port": port,
            "state": "open" if result == 0 else "closed",
            "service": socket.getservbyport(port) if result == 0 else "unknown"
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
    return [r for r in results if r["state"] == "open"]
