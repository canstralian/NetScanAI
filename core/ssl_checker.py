import ssl
import socket
import datetime
from typing import Dict, Optional
import logging

def check_ssl_certificate(host: str, port: int = 443) -> Optional[Dict]:
    """Check SSL certificate information for a given host."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=3.0) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                
                # Extract relevant certificate information
                not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                not_before = datetime.datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                issuer = dict(x[0] for x in cert['issuer'])
                subject = dict(x[0] for x in cert['subject'])
                
                return {
                    'valid': True,
                    'issuer': issuer.get('organizationName', 'Unknown'),
                    'subject': subject.get('commonName', host),
                    'valid_from': not_before.strftime('%Y-%m-%d'),
                    'valid_until': not_after.strftime('%Y-%m-%d'),
                    'version': ssock.version(),
                    'cipher': ssock.cipher()[0]
                }
                
    except ssl.SSLError as e:
        logging.error(f"SSL Error for {host}:{port} - {str(e)}")
        return {'valid': False, 'error': 'SSL Error: ' + str(e)}
    except socket.error as e:
        logging.error(f"Socket Error for {host}:{port} - {str(e)}")
        return {'valid': False, 'error': 'Connection Error: ' + str(e)}
    except Exception as e:
        logging.error(f"General Error checking SSL for {host}:{port} - {str(e)}")
        return {'valid': False, 'error': 'Error: ' + str(e)}
