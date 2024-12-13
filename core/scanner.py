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

from .ssl_checker import check_ssl_certificate

async def scan_port(target: str, port: int) -> Dict:
    """Scan a single port and gather additional security information."""
    try:
        # Common ports and their services
        common_ports = {
            20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet",
            25: "smtp", 53: "dns", 80: "http", 110: "pop3",
            143: "imap", 443: "https", 445: "microsoft-ds", 465: "smtps", 
            587: "submission", 993: "imaps", 995: "pop3s", 1433: "mssql",
            1521: "oracle", 2049: "nfs", 3306: "mysql", 3389: "rdp",
            5432: "postgresql", 5900: "vnc", 6379: "redis", 8080: "http-alt", 
            8443: "https-alt", 9200: "elasticsearch", 27017: "mongodb"
        }

        def get_service_banner(sock: socket.socket, service: str) -> str:
            """Get service banner using basic protocol commands."""
            try:
                if service == "http":
                    sock.send(b"HEAD / HTTP/1.1\r\nHost: "+target.encode()+b"\r\n\r\n")
                    response = sock.recv(1024).decode('utf-8', errors='ignore')
                    for line in response.split('\n'):
                        if line.startswith('Server:'):
                            return line.split(':', 1)[1].strip()
                elif service == "ssh":
                    response = sock.recv(1024).decode('utf-8', errors='ignore')
                    if response.startswith('SSH-'):
                        return response.strip()
                elif service == "ftp":
                    response = sock.recv(1024).decode('utf-8', errors='ignore')
                    return response.strip()
            except Exception as e:
                logging.debug(f"Banner detection error for {service} on port {port}: {str(e)}")
            return ""

        # Initial connection check
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)  # Increased timeout for better reliability
        
        result = sock.connect_ex((target, port))
        
        service = "unknown"
        service_info = ""
        
        if result == 0:
            try:
                # Get default service name
                service = socket.getservbyport(port)
            except (OSError, socket.error):
                service = common_ports.get(port, "unknown")
            
            # Try to get service banner
            try:
                # For services that need immediate banner reading
                if service in ["ssh", "ftp"]:
                    banner = get_service_banner(sock, service)
                    if banner:
                        service_info = f"({banner})"
                
                # For HTTP-like services
                elif service in ["http", "https", "http-alt", "https-alt"]:
                    banner = get_service_banner(sock, "http")
                    if banner:
                        service_info = f"({banner})"
                
                if service_info:
                    service = f"{service} {service_info}"
                    
            except Exception as e:
                logging.debug(f"Service detection error on port {port}: {str(e)}")
        
        sock.close()
        # Gather additional security information for relevant services
        security_info = {}
        if result == 0 and service in ['https', 'https-alt']:
            ssl_info = check_ssl_certificate(target, port)
            if ssl_info:
                security_info['ssl'] = ssl_info

        return {
            "port": port,
            "state": "open" if result == 0 else "closed",
            "service": service,
            "security_info": security_info
        }
            
    except Exception as e:
        logging.error(f"Error scanning port {port}: {str(e)}")
        try:
            sock.close()
        except:
            pass
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
