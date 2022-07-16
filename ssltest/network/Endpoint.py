import logging
import socket
import ssl

from OpenSSL import SSL

from .SSLv2 import SSLv2
from .SSLv3 import SSLv3
from ..core.utils import convert_cipher_suite
from ..sockets.SecureSafeSocket import SecureSafeSocket

log = logging.getLogger(__name__)


class Endpoint:
    def __init__(self, sock_addr, supported_protocols, args):
        self.sock_addr = sock_addr
        self.supported_protocols = supported_protocols
        self.worst = args.worst
        self.cert_chain = args.cert_chain
        self.certificates = None
        self.cert_verified = None
        self.cipher_suite = None
        self.protocol = None

    def scan_endpoint(self):
        """
        Gather objects required to rate an endpoint

        Use functions in this module to create a connection and get the
        servers certificate, cipher suite and protocol used in the connection.
        """
        log.info("Creating main session")
        protocol = self.choose_protocol()
        if "SSL" in protocol:
            log.info("Connecting with SSL")
            ssl_protocols = {"SSLv3": SSLv3, "SSLv2": SSLv2}
            ssl_conn = ssl_protocols[protocol](self.sock_addr)
            ssl_conn.connect()
            self.cipher_suite = ssl_conn.parse_cipher_suite()
            self.certificates = ssl_conn.parse_certificate()
            self.cert_verified = ssl_conn.verify_cert()
            self.protocol = ssl_conn.protocol
        else:
            log.info("Connecting with TLS")
            with SecureSafeSocket(
                self.sock_addr, protocol, True, "tlsv1.n_scan"
            ) as sock:
                sock.connect()
                self.cert_verified = sock.cert_verified
                self.cipher_suite, self.protocol = self.get_cipher_suite_and_protocol(
                    sock.sock
                )
            self.certificates = self.get_certificate()

    def choose_protocol(self):
        """
        Find the protocol version which will be used to connect to the server

        :return: The string of the chosen protocol or an empty string
        :rtype: str
        """
        tls_protocols = list(filter(lambda p: "TLS" in p, self.supported_protocols))
        if not self.worst and len(tls_protocols) != 0:
            return "TLSvAUTO"
        return self.worst_or_best_protocol(self.supported_protocols, self.worst)

    def get_certificate(self):
        """
        Gather a certificate in the DER binary format

        :return: List of endpoints certificates
        :rtype: list[cryptography.x509.Certificate]
        """
        ctx = SSL.Context(SSL.SSLv23_METHOD)
        ssl_socket = socket.create_connection(self.sock_addr)
        ssl_socket = SSL.Connection(ctx, ssl_socket)
        ssl_socket.set_tlsext_host_name(bytes(self.sock_addr.url, "utf-8"))
        ssl_socket.set_connect_state()
        ssl_socket.do_handshake()
        cert_chain = ssl_socket.get_peer_cert_chain()
        if self.cert_chain:
            return [cert.to_cryptography() for cert in cert_chain]
        return [cert_chain[0].to_cryptography()]

    @staticmethod
    def worst_or_best_protocol(supported_protocols, worst):
        """
        Find either the best or worst protocol to connect with

        :param list supported_protocols: Supported protocols by the server
        :param bool worst: Whether to find the worst available protocol or best
        :return: The string of the chosen protocol
        :rtype: str
        """
        protocol_strengths = {
            "TLSv1.3": 5,
            "TLSv1.2": 4,
            "TLSv1.1": 3,
            "TLSv1.0": 2,
            "SSLv3": 1,
            "SSLv2": 0,
        }
        # If worst option is False the best SSL protocol is found
        # If worst option is True the worst protocol is found, in other words the minimum value is found
        switcher = {True: min, False: max}
        # Filter out the unsupported protocols
        filtered_protocol_strengths = {
            k: v for k, v in protocol_strengths.items() if k in supported_protocols
        }
        return switcher[worst](filtered_protocol_strengths)

    @staticmethod
    def get_cipher_suite_and_protocol(sock):
        """
        Gather the cipher suite and the protocol from a ssl socket

        :param ssl.SSLSocket sock: Established socket
        :return: Negotiated cipher suite and SSL/TLS protocol
        :rtype: tuple[str, str]
        """
        cipher_suite = sock.cipher()[0]
        if "-" in cipher_suite:
            log.warning(f"{cipher_suite} not in IANA format, converting")
            cipher_suite = convert_cipher_suite(cipher_suite, "OpenSSL", "IANA")
        return cipher_suite, sock.version()
