import logging
import socket
import ssl

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from .SSLv3 import SSLv3
from .SSLv2 import SSLv2
from ...utils import incremental_sleep, convert_cipher_suite


def get_website_info(url, port, supported_protocols, worst):
    """
    Gather objects required to rate a web server

    Uses functions in this module to create a connection and get the
    servers certificate, cipher suite and protocol used in the connection.

    :param int port: Port to scan on
    :param str url: Url of the webserver
    :param list supported_protocols: Supported SSL/TLS protocol versions
    :param bool worst: Whether to connect with the worst available protocol
    :return:
        certificate -- Used certificate to verify the server,
        cert_verified -- Is certificate verified,
        cipher_suite -- Negotiated cipher suite,
        protocol -- Protocol name and version,
    :rtype: tuple
    """
    logging.info('Creating main session...')
    chosen_protocol = choose_protocol(supported_protocols, worst)
    if 'TLS' in chosen_protocol:
        logging.debug('Connecting with TLS...')
        context = create_ssl_context(chosen_protocol)
        ssl_socket, cert_verified = create_session(url, port, True, context)
        cipher_suite, protocol = get_cipher_suite_and_protocol(ssl_socket)
        certificate = get_certificate(ssl_socket)
        ssl_socket.close()
    else:
        logging.debug('Connecting with SSL...')
        ssl_protocols = {
            'SSLv3': SSLv3,
            'SSLv2': SSLv2
        }
        ssl_protocol = ssl_protocols[chosen_protocol](url, port)
        ssl_protocol.send_client_hello()
        ssl_protocol.parse_cipher_suite()
        ssl_protocol.parse_certificate()
        ssl_protocol.verify_cert()
        cipher_suite = ssl_protocol.cipher_suite
        certificate = ssl_protocol.certificates[0]
        cert_verified = ssl_protocol.cert_verified
        protocol = ssl_protocol.protocol
    return certificate, cert_verified, cipher_suite, protocol


def choose_protocol(protocols, worst):
    """
    Find the protocol version which will be used to connect to the server

    :param protocols: Supported protocols by the server
    :param bool worst: Whether to find worst available protocol or best
    :return: The string of the chosen protocol
    :rtype: str
    """
    protocol_strengths = {
        'TLSv1.3': 5,
        'TLSv1.2': 4,
        'TLSv1.1': 3,
        'TLSv1.0': 2,
        'SSLv3': 1,
        'SSLv2': 0
    }
    items = list(protocol_strengths.items())
    # Switcher for either the best protocol or the worst
    # If worst option is False the best protocol is found, in other words the maximum value is found
    # If worst option is True the worst protocol is found, in other words the minimum value is found
    switcher = {
        True: (lambda a, b: a < b, items[0]),
        False: (lambda a, b: a > b, items[-1])
    }
    # Filter out the unsupported protocols
    filtered_protocol_strengths = dict(filter(lambda item: item[0] in protocols, protocol_strengths.items()))
    base = switcher[worst][1]
    comparison = switcher[worst][0]
    for key, value in filtered_protocol_strengths.items():
        if comparison(value, base[1]):
            base = (key, value)
    return base[0]


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
        cipher_suite = convert_cipher_suite(cipher_suite, 'OpenSSL', 'IANA')
    return cipher_suite, ssl_socket.version()


def create_session(url, port, verify_cert, context):
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
            context.verify_mode = ssl.VerifyMode.CERT_NONE
        except socket.timeout:
            logging.debug('connection timeout...')
            sleep = incremental_sleep(sleep, Exception('Connection timeout'), 3)
        except socket.gaierror:
            raise Exception('DNS record not found')
        except socket.error as e:
            error_str = e.args[1]
            # Protocol not supported, no need to sleep
            if '[SSL: UNSUPPORTED_PROTOCOL]' in error_str or \
                    '[SSL: SSLV3_ALERT_HANDSHAKE_FAILURE]' in error_str or \
                    '[SSL: TLSV1_ALERT_PROTOCOL_VERSION]' in error_str:
                logging.debug('protocol unsupported...')
                raise e
            logging.debug('error occurred...')
            sleep = incremental_sleep(sleep, e, 3)
        ssl_socket.close()
    return ssl_socket, cert_verified


def create_ssl_context(protocol_version):
    """
    Create an ssl context from the native ssl library for the specific protocol version

    :param str protocol_version: Protocol version to create the context with
    :return: Created SSL context
    :rtype: ssl.SSLContext
    """
    ssl_versions = {
        'TLSv1.0': ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_3 | ssl.OP_NO_SSLv3,
        'TLSv1.1': ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_3 | ssl.OP_NO_SSLv3,
        'TLSv1.2': ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_3 | ssl.OP_NO_SSLv3,
        'TLSv1.3': ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1 | ssl.OP_NO_SSLv3,
    }
    context = ssl.create_default_context()
    context.options = ssl.OP_ALL
    context.options |= ssl_versions[protocol_version]
    return context
