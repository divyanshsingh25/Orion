import ssl
import socket
from datetime import datetime
import asyncio

async def analyze_tls(host: str, port: int = 443) -> dict:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _analyze_tls_sync, host, port)

def _analyze_tls_sync(host: str, port: int) -> dict:
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    # In CERT_NONE, getpeercert() returns {} unless we ask for binary and decode, or just use another method.
                    # Wait, if verify_mode is CERT_NONE, we need binary form.
                    der_cert = ssock.getpeercert(binary_form=True)
                    if der_cert:
                        import OpenSSL
                        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, der_cert)

                        issuer = x509.get_issuer().CN or x509.get_issuer().O or "Unknown Issuer"
                        subject = x509.get_subject().CN or host

                        not_after = x509.get_notAfter()
                        if not_after:
                            dt = datetime.strptime(not_after.decode('ascii'), "%Y%m%d%H%M%SZ")
                            expiry_str = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
                        else:
                            expiry_str = "Unknown"

                        return {
                            "subject": subject,
                            "issuer": issuer,
                            "expiry": expiry_str,
                            "valid": True
                        }

                return {
                    "subject": host,
                    "issuer": "Could not parse certificate",
                    "expiry": "N/A"
                }
    except Exception as e:
        return {
            "error": str(e),
            "subject": "Error retrieving TLS",
            "issuer": "Error retrieving TLS",
            "expiry": "N/A"
        }
