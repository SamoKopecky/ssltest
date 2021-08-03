import ssl
import socket
import logging

from OpenSSL import SSL
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from ..utils import convert_openssh_to_iana, incremental_sleep
from ..exceptions.UnknownConnectionError import UnknownConnectionError
from ..exceptions.ConnectionTimeoutError import ConnectionTimeoutError
from ..exceptions.DNSError import DNSError
from ssl_scan.SSLv3 import SSLv3


def get_website_info(url: str, port: int):
    """
    Gather objects to be used in rating a web server.

    Uses functions in this module to create a connection and get the
    servers certificate, cipher suite and protocol used in the connection.
    :param port: port to scan on
    :param url: url of the webserver
    :return:
        certificate -- used certificate to verify the server
        cipher_suite -- negotiated cipher suite
        protocol -- protocol name and version
    """
    logging.info('Creating session...')
    try:
        ssl_socket, cert_verified = create_session(url, port)
        cipher_suite, protocol = get_cipher_suite_and_protocol(ssl_socket)
        certificate = get_certificate(ssl_socket)
        ssl_socket.close()
    except ssl.SSLError:
        sslv3 = SSLv3(url, port)
        sslv3.parse_cipher_suite()
        sslv3.parse_certificate()
        cipher_suite = sslv3.cipher_suite
        certificate = sslv3.certificate
        cert_verified = sslv3.cert_verified
        protocol = sslv3.protocol

    return certificate, cert_verified, cipher_suite, protocol


def get_certificate(ssl_socket: ssl.SSLSocket):
    """
    Gather a certificate in a der binary format.

    :param ssl_socket: secured socket
    :return: gathered certificate
    """
    certificate_pem = bytes(ssl_socket.getpeercert(binary_form=True))
    return x509.load_der_x509_certificate(certificate_pem, default_backend())


def get_cipher_suite_and_protocol(ssl_socket: ssl.SSLSocket):
    """
    Gather the cipher suite and the protocol from the ssl_socket.

    :param ssl_socket: secure socket
    :return: negotiated cipher suite and the protocol
    """
    cipher_suite = ssl_socket.cipher()[0]
    if '-' in cipher_suite:
        cipher_suite = convert_openssh_to_iana(cipher_suite)
    return cipher_suite, ssl_socket.version()


def create_session_pyopenssl(url: str, port: int, context: SSL.Context):
    """
    Create a secure connection to any server on any port with a defined context.

    This function creates a secure connection with pyopenssl lib. Original ssl lib
    doesn't work with older TLS versions on some OpenSSL implementations and thus
    the program can't scan for all supported versions.
    :param url: url of the website
    :param context: ssl context
    :param port: port
    :return: created secure socket
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssl_socket = SSL.Connection(context, sock)
    sleep = 0
    # Loop until there is a valid response or after 15 seconds
    while True:
        try:
            logging.debug(f'connecting... (tls version scanning)')
            ssl_socket.connect((url, port))
            break
        except OSError as e:
            sleep = incremental_sleep(sleep, e, 5)
    ssl_socket.do_handshake()
    return ssl_socket


def create_session(url: str, port: int, context: ssl.SSLContext = ssl.create_default_context()):
    """
    Create a secure connection to any server on any port with a defined context
    on a specific timeout.

    :param url: url of the website
    :param context: ssl context
    :param port: port
    :return: created secure socket
    """
    cert_verified = True
    context.check_hostname = True
    context.verify_mode = ssl.VerifyMode.CERT_REQUIRED
    sleep = 0
    # Loop until there is a valid response or after 15 seconds
    # because of rate limiting on some servers
    while True:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)  # in seconds
        ssl_socket = context.wrap_socket(sock, server_hostname=url)
        try:
            logging.debug(f'connecting... (main connection)')
            ssl_socket.connect((url, port))
            break
        except ssl.SSLCertVerificationError:
            cert_verified = False
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        except socket.timeout:
            raise ConnectionTimeoutError()
        except socket.gaierror:
            raise DNSError()
        except ConnectionResetError as e:
            raise UnknownConnectionError(e)
        except socket.error as e:
            ssl_socket.close()
            sleep = incremental_sleep(sleep, e, 1)
    return ssl_socket, cert_verified
