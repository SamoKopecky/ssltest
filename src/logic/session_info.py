import sys
import ssl
from socket import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend

sys.path.append('../../')

from src.utils import convert_openssh_to_iana


def get_website_info(hostname):
    ssl_socket = create_session(hostname)
    cipher_suite, protocol = get_cipher_suite_and_protocol(ssl_socket)
    cert = get_certificate(ssl_socket)
    ssl_socket.close()
    return cert, cipher_suite, protocol


def get_certificate(ssl_socket):
    cert_pem = bytes(ssl_socket.getpeercert(binary_form=True))
    cert = x509.load_der_x509_certificate(cert_pem, default_backend())
    return cert


def get_cipher_suite_and_protocol(ssl_socket):
    cipher = ssl_socket.cipher()
    cipher_suite = cipher[0]
    if '-' in cipher_suite:
        cipher_suite = convert_openssh_to_iana(cipher_suite)
    return cipher_suite, cipher[1]


def create_session(hostname):
    ctx = ssl.create_default_context()
    ssl_socket = ctx.wrap_socket(socket(), server_hostname=hostname)
    ssl_socket.connect((hostname, 443))
    return ssl_socket
