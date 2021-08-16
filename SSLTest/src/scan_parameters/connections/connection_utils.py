import logging
import socket
import ssl

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from .SSLv3 import SSLv3
from .SSLv2 import SSLv2
from ..utils import convert_openssh_to_iana, incremental_sleep


def get_website_info(url, port, supported_protocols):
    """
    Gather objects required to rate a web server

    Uses functions in this module to create a connection and get the
    servers certificate, cipher suite and protocol used in the connection.
    :param int port: Port to scan on
    :param str url: Url of the webserver
    :param list supported_protocols: Supported SSL/TLS protocol versions
    :return:
        certificate -- Used certificate to verify the server
        cert_verified -- Is certificate verified
        cipher_suite -- Negotiated cipher suite
        protocol -- Protocol name and version
    """
    logging.info('Creating main session...')
    try:
        ssl_socket, cert_verified = create_session(url, port, True)
        cipher_suite, protocol = get_cipher_suite_and_protocol(ssl_socket)
        certificate = get_certificate(ssl_socket)
        ssl_socket.close()
    except (ssl.SSLError, ConnectionResetError) as e:
        ssl_protocols = [
            SSLv3(url, port),
            SSLv2(url, port)
        ]
        chosen_protocol = ssl_protocols[0]
        if ['SSLv2'] == supported_protocols:
            chosen_protocol = ssl_protocols[1]
        chosen_protocol.send_client_hello()
        chosen_protocol.parse_cipher_suite()
        chosen_protocol.parse_certificate()
        chosen_protocol.verify_cert()
        cipher_suite = chosen_protocol.cipher_suite
        certificate = chosen_protocol.certificates[0]
        cert_verified = chosen_protocol.cert_verified
        protocol = chosen_protocol.protocol

    return certificate, cert_verified, cipher_suite, protocol


def get_certificate(ssl_socket):
    """
    Gather a certificate in the DER binary format

    :param ssl.SSLSocket ssl_socket: Established socket
    :return: Gathered certificate
    """
    certificate_pem = bytes(ssl_socket.getpeercert(binary_form=True))
    return x509.load_der_x509_certificate(certificate_pem, default_backend())


def get_cipher_suite_and_protocol(ssl_socket: ssl.SSLSocket):
    """
    Gather the cipher suite and the protocol from the ssl_socket

    :param ssl.SSLSocket ssl_socket: Established socket
    :return: Negotiated cipher suite and SSL/TLS protocol
    """
    cipher_suite = ssl_socket.cipher()[0]
    if '-' in cipher_suite:
        cipher_suite = convert_openssh_to_iana(cipher_suite)
    return cipher_suite, ssl_socket.version()


def create_session(url, port, verify_cert, context=ssl.SSLContext()):
    """
    Create a secure connection to any server on any port with a defined context

    :param str url: Url of the website
    :param int port: Port to create the connection on
    :param bool verify_cert: Whether to verify the certificate or not
    :param ssl.SSLContext context: ssl context
    :return: Created secure socket
    """
    cert_verified = True
    if verify_cert:
        context.check_hostname = True
        context.verify_mode = ssl.VerifyMode.CERT_REQUIRED
    context.set_ciphers('ALL')
    sleep = 0
    # Loop until there is a valid response or after a timeout
    # because of rate limiting on some servers
    while True:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)  # in seconds
        ssl_socket = context.wrap_socket(sock, server_hostname=url)
        try:
            logging.debug(f'connecting...')
            ssl_socket.connect((url, port))
            break
        except ssl.SSLCertVerificationError:
            # If cert is was unverified, connect again without verifying
            cert_verified = False
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        except socket.timeout:
            logging.debug('connection timeout...')
            sleep = incremental_sleep(sleep, Exception('Connection timeout'), 3)
        except socket.gaierror:
            raise Exception('DNS record not found')
        except socket.error as e:
            ssl_socket.close()
            error_str = e.args[1]
            # Protocol not supported, no need to sleep
            if '[SSL: UNSUPPORTED_PROTOCOL]' in error_str or \
                    '[SSL: SSLV3_ALERT_HANDSHAKE_FAILURE]' in error_str:
                logging.debug('protocol unsupported...')
                raise e
            logging.debug('error occurred...')
            sleep = incremental_sleep(sleep, e, 3)
    return ssl_socket, cert_verified
