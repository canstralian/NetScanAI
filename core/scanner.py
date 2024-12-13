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
            143: "imap", 443: "https", 445: "microsoft-ds", 465: "smtps", 
            587: "submission", 993: "imaps", 995: "pop3s", 1433: "mssql",
            1521: "oracle", 2049: "nfs", 3306: "mysql", 3389: "rdp",
            5432: "postgresql", 5900: "vnc", 6379: "redis", 8080: "http-alt", 
            8443: "https-alt", 9200: "elasticsearch", 27017: "mongodb",
            6000: "x11", 11211: "memcached", 27015: "steam", 
            5601: "kibana", 9090: "prometheus", 9100: "node-exporter"
        }
        
        # Advanced service detection functions
        async def detect_ssh_version(target: str, port: int) -> str:
            try:
                reader, writer = await asyncio.open_connection(target, port)
                banner = await reader.read(50)
                writer.close()
                await writer.wait_closed()
                return banner.decode().strip()
            except:
                return ""

        async def detect_ftp_banner(target: str, port: int) -> str:
            try:
                reader, writer = await asyncio.open_connection(target, port)
                banner = await reader.read(100)
                writer.close()
                await writer.wait_closed()
                return banner.decode().strip()
            except:
                return ""
        
        result = sock.connect_ex((target, port))
        sock.close()
        
        service = "unknown"
        service_info = ""
        
        if result == 0:
            try:
                service = socket.getservbyport(port)
            except (OSError, socket.error):
                service = common_ports.get(port, "unknown")
                
            # Enhanced service detection
            if service == "ssh":
                banner = await detect_ssh_version(target, port)
                if banner:
                    service_info = f"({banner})"
            elif service == "ftp":
                banner = await detect_ftp_banner(target, port)
                if banner:
                    service_info = f"({banner})"
            
            if service_info:
                service = f"{service} {service_info}"
                
            # Enhanced service detection
            if service in ["http", "https", "http-alt", "https-alt"]:
                try:
                    protocol = "https" if service in ["https", "https-alt"] else "http"
                    with socket.create_connection((target, port), timeout=1) as s:
                        # Try multiple request methods for better fingerprinting
                        methods = ["HEAD", "GET", "OPTIONS"]
                        headers = []
                        for method in methods:
                            try:
                                s.send(f"{method} / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: SecurityScanner/1.0\r\n\r\n".encode())
                                response = s.recv(1024).decode()
                                headers.extend([line.strip() for line in response.split("\r\n") if line.strip()])
                            except:
                                continue
                        
                        # Extract useful information
                        server_info = []
                        for header in headers:
                            if header.startswith(("Server:", "X-Powered-By:", "X-AspNet-Version:")):
                                server_info.append(header.split(":", 1)[1].strip())
                        
                        if server_info:
                            service = f"{service} ({', '.join(server_info)})"
                except Exception as e:
                    logging.debug(f"HTTP detection error on port {port}: {str(e)}")
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
