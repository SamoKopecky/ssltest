import sys
import ssl
from socket import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend

sys.path.append('../../')

from src.utils import convert_openssh_to_iana


def get_website_info(hostname):
    ssl_socket, supported_versions = test_ssl_versions(hostname)
    cipher_suite, protocol = get_cipher_suite_and_protocol(ssl_socket)
    cert = get_certificate(ssl_socket)
    ssl_socket.close()
    return cert, cipher_suite, protocol, supported_versions


def get_certificate(ssl_socket):
    cert_pem = bytes(ssl_socket.getpeercert(binary_form=True))
    cert = x509.load_der_x509_certificate(cert_pem, default_backend())
    return cert


def get_cipher_suite_and_protocol(ssl_socket):
    cipher = ssl_socket.cipher()
    cipher_suite = cipher[0]
    if '-' in cipher_suite:
        cipher_suite = convert_openssh_to_iana(cipher_suite)
    return cipher_suite, ssl_socket.version()


def test_ssl_versions(hostname):
    ssl_versions = [
        ssl.Options.OP_NO_TLSv1_3,
        ssl.Options.OP_NO_TLSv1_2,
        ssl.Options.OP_NO_TLSv1_1,
        ssl.Options.OP_NO_TLSv1,
        ssl.Options.OP_NO_SSLv3,
        ssl.Options.OP_NO_SSLv2
    ]
    max_version_socket = None
    supported_protocols = []
    for i in range(len(ssl_versions)):
        ssl_versions.pop()
        ctx = ssl.SSLContext()
        ctx.options -= ssl.Options.OP_NO_SSLv3
        for version in ssl_versions:
            ctx.options += version
        try:
            max_version_socket = create_session(hostname, ctx, 443)
            version = max_version_socket.version()
            if version not in supported_protocols:
                supported_protocols.append(version)
        except ssl.SSLError:
            pass
    return max_version_socket, supported_protocols


def create_session(hostname, ctx, port):
    ssl_socket = ctx.wrap_socket(socket(), server_hostname=hostname)
    ssl_socket.connect((hostname, port))
    return ssl_socket
