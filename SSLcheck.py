import socket
import ssl
import OpenSSL.crypto
import sys

def get_supported_protocols(host, port):
    protocols = {
        'SSLv3': ssl.PROTOCOL_SSLv3,
        'TLSv1': ssl.PROTOCOL_TLSv1,
        'TLSv1.1': ssl.PROTOCOL_TLSv1_1,
        'TLSv1.2': ssl.PROTOCOL_TLSv1_2,
        'TLSv1.3': ssl.PROTOCOL_TLS
    }
    supported_protocols = []

    for protocol_name, protocol in protocols.items():
        try:
            context = ssl.SSLContext(protocol)
            with socket.create_connection((host, port)) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    supported_protocols.append(protocol_name)
        except ssl.SSLError:
            pass
        except Exception as e:
            print(f"Error testing protocol {protocol_name}: {e}", file=sys.stderr)

    return supported_protocols

def get_supported_ciphers(host, port, protocols):
    supported_ciphers = []
    for protocol in protocols:
        try:
            context = ssl.SSLContext(getattr(ssl, f'PROTOCOL_{protocol.upper()}'))
            context.set_ciphers('ALL')
            with socket.create_connection((host, port)) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher = ssock.cipher()
                    if cipher not in supported_ciphers:
                        supported_ciphers.append(cipher)
        except ssl.SSLError:
            pass
        except Exception as e:
            print(f"Error testing ciphers for protocol {protocol}: {e}", file=sys.stderr)

    return supported_ciphers

def test_tls_fallback(host, port):
    # Testing for TLS_FALLBACK_SCSV support
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        context.set_ciphers('ALL:@SECLEVEL=0')
        context.set_options(ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1)
        with socket.create_connection((host, port)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                return True
    except ssl.SSLError:
        return False

def get_certificate(host, port):
    context = ssl.create_default_context()
    with socket.create_connection((host, port)) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            der_cert = ssock.getpeercert(True)
            return ssl.DER_cert_to_PEM_cert(der_cert)

def print_certificate_info(pem_cert):
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem_cert)
    print("\nCertificate:")
    print("  Subject:", cert.get_subject())
    print("  Issuer:", cert.get_issuer())
    print("  Valid from:", cert.get_notBefore().decode())
    print("  Valid until:", cert.get_notAfter().decode())

def main(host, port):
    print(f"\nTesting SSL/TLS configurations for {host}:{port}")

    print("\n1. Testing supported protocols:")
    supported_protocols = get_supported_protocols(host, port)
    print("Supported Protocols:", supported_protocols)

    print("\n2. Testing supported ciphers:")
    supported_ciphers = get_supported_ciphers(host, port, supported_protocols)
    print("Supported Ciphers:", supported_ciphers)

    print("\n3. Testing for TLS Fallback:")
    tls_fallback_support = test_tls_fallback(host, port)
    print("TLS Fallback SCSV support:", tls_fallback_support)

    print("\n4. Fetching SSL/TLS Certificate:")
    pem_cert = get_certificate(host, port)
    print_certificate_info(pem_cert)

if __name__ == "__main__":
    target_host = "www.example.com"  # Replace with the target host
    target_port = 443  # Replace with the target port, usually 443 for HTTPS
    main(target_host, target_port)
