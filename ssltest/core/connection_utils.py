import logging
import socket
import ssl
from typing import NamedTuple

from OpenSSL import SSL

from .SSLv2 import SSLv2
from .SSLv3 import SSLv3
from ..main.utils import convert_cipher_suite
from ..network.SecureSafeSocket import SecureSafeSocket
from ..network.SocketAddress import SocketAddress


class WebServer(NamedTuple):
    certificates: list
    cert_verified: bool
    cipher_suite: str
    protocol: str


log = logging.getLogger(__name__)


def get_web_server_info(address, supported_protocols, args):
    """
    Gather objects required to rate a web server

    Use functions in this module to create a connection and get the
    servers certificate, cipher suite and protocol used in the connection.

    :param args:
    :param SocketAddress address: Webserver address
    :param list supported_protocols: Supported SSL/TLS protocol versions
    :return: Tuple of all the values
    :rtype: WebServer
    """
    log.info('Creating main session')
    protocol = choose_protocol(supported_protocols, args.worst)
    if 'SSL' in protocol:
        log.info('Connecting with SSL')
        ssl_protocols = {
            'SSLv3': SSLv3,
            'SSLv2': SSLv2
        }
        ssl_protocol = ssl_protocols[protocol](address)
        ssl_protocol.connect()
        ssl_protocol.parse_cipher_suite()
        ssl_protocol.parse_certificate()
        ssl_protocol.verify_cert()
        cipher_suite = ssl_protocol.cipher_suite
        certificates = ssl_protocol.certificates
        cert_verified = ssl_protocol.cert_verified
        protocol = ssl_protocol.protocol
    else:
        log.info('Connecting with TLS')
        with SecureSafeSocket(address, protocol, True, 'tlsv1.n_scan') as sock:
            sock.connect()
            cert_verified = sock.cert_verified
            cipher_suite, protocol = get_cipher_suite_and_protocol(sock.sock)
        certificates = get_certificate(address, args.cert_chain)
    webserver_info = WebServer(
        certificates, cert_verified, cipher_suite, protocol)
    return webserver_info


def choose_protocol(protocols, worst):
    """
    Find the protocol version which will be used to connect to the server

    :param list protocols: Supported protocols by the server
    :param bool worst: Whether to find the worst available protocol or best
    :return: The string of the chosen protocol or an empty string
    :rtype: str
    """
    tls_protocols = list(filter(lambda p: 'TLS' in p, protocols))
    if not worst and len(tls_protocols) != 0:
        return 'TLSvAUTO'
    return worst_or_best_protocol(protocols, worst)


def worst_or_best_protocol(protocols, worst):
    """
    Find either the best or worst protocol to connect with

    :param list protocols: Supported protocols by the server
    :param bool worst: Whether to find the worst available protocol or best
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
    # If worst option is False the best SSL protocol is found
    # If worst option is True the worst protocol is found, in other words the minimum value is found
    switcher = {
        True: min,
        False: max
    }
    # Filter out the unsupported protocols
    filtered_protocol_strengths = {
        k: v for k, v in protocol_strengths.items() if k in protocols}
    return switcher[worst](filtered_protocol_strengths)


def get_certificate(address, scan_cert_chain):
    """
    Gather a certificate in the DER binary format

    :param SocketAddress address: Web server address
    :param bool scan_cert_chain: Scan the whole cert chain
    :return: Gathered certificate/certificates
    :rtype: Any
    """
    ctx = SSL.Context(SSL.SSLv23_METHOD)
    ssl_socket = socket.create_connection((address.url, address.port))
    ssl_socket = SSL.Connection(ctx, ssl_socket)
    ssl_socket.set_tlsext_host_name(bytes(address.url, 'utf-8'))
    ssl_socket.set_connect_state()
    ssl_socket.do_handshake()
    cert_chain = ssl_socket.get_peer_cert_chain()
    if scan_cert_chain:
        return [cert.to_cryptography() for cert in cert_chain]
    return [cert_chain[0].to_cryptography()]


def get_cipher_suite_and_protocol(ssl_socket):
    """
    Gather the cipher suite and the protocol from the ssl_socket

    :param ssl.SSLSocket ssl_socket: Established socket
    :return: Negotiated cipher suite and SSL/TLS protocol
    """
    cipher_suite = ssl_socket.cipher()[0]
    if '-' in cipher_suite:
        log.warning(f'{cipher_suite} not in IANA format, converting')
        cipher_suite = convert_cipher_suite(cipher_suite, 'OpenSSL', 'IANA')
    return cipher_suite, ssl_socket.version()
