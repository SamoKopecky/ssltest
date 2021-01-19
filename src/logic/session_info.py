import sys
import ssl
import socket
import traceback
from cryptography import x509
from cryptography.hazmat.backends import default_backend

sys.path.append('../../')

from src.utils import convert_openssh_to_iana


def get_website_info(hostname):
    """
    Gathers all the required information to rate a web server.

    :param hostname: hostname of the webserver
    :return:
        cert -- used certificate to verify the server
        cipher_suite -- negotiated cipher suite
        protocol -- protocol name and version
        supported_versions -- SSL/TLS versions that the web server supports
    """
    ssl_socket, supported_versions = test_ssl_versions(hostname)
    cipher_suite, protocol = get_cipher_suite_and_protocol(ssl_socket)
    cert = get_certificate(ssl_socket)
    ssl_socket.close()
    return cert, cipher_suite, protocol, supported_versions


def get_certificate(ssl_socket):
    """
    Gathers a certificate in a der format.

    :param ssl_socket: secured socket
    :return: gathered certificate
    """
    cert_pem = bytes(ssl_socket.getpeercert(binary_form=True))
    cert = x509.load_der_x509_certificate(cert_pem, default_backend())
    return cert


def get_cipher_suite_and_protocol(ssl_socket):
    """
    Gathers the cipher suite and the protocol from the ssl_socket.

    :param ssl_socket: secure socket
    :return: negotiated cipher suite and the protocol
    """
    cipher = ssl_socket.cipher()
    cipher_suite = cipher[0]
    if '-' in cipher_suite:
        cipher_suite = convert_openssh_to_iana(cipher_suite)
    return cipher_suite, ssl_socket.version()


def test_ssl_versions(hostname):
    """
    Tests for all possible SSL/TLS versions which the server supports

    :param hostname: hostname of the website
    :return: secure socket with the highest version and the supported protocols
    """
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
    """
    Creates a secure connection to any server on any port with a defined context.

    :param hostname: hostname of the website
    :param ctx: ssl context
    :param port: port
    :return: created secure socket
    """
    ssl_socket = ctx.wrap_socket(socket.socket(), server_hostname=hostname)
    ssl_socket.connect((hostname, port))
    return ssl_socket
