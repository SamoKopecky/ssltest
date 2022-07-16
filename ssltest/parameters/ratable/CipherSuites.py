import logging

from .CipherSuite import CipherSuite
from ...core.utils import (
    parse_cipher_suite,
    bytes_to_cipher_suite,
    protocol_version_conversion,
    get_cipher_suite_protocols,
)
from ...network.ClientHello import ClientHello
from ...network.SSLv2 import SSLv2
from ...sockets.SafeSocket import SafeSocket
from ...sockets.SocketAddress import SocketAddress

log = logging.getLogger(__name__)


class CipherSuites:
    def __init__(self, address, supported_protocols):
        """
        Constructor

        :param SocketAddress address: Webserver address
        :param list[str] supported_protocols: Webserver supported SSL/TLS protocols
        """
        self.address = address
        self.supported = {}
        self.unrated = {}
        self.supported_protocols = supported_protocols
        self.tested_cipher_suites = bytearray()

    def scan_cipher_suites(self, only_sslv2):
        """
        Scan the supported cipher suites by the web server

        For each protocol a client hello is sent with all of the
        possible cipher suites. When the server response with a valid
        message a cipher suite chosen by the server is removed from the
        possible cipher suites that the client sends. If the server response
        with an error of some kind the supported cipher suites are those
        which the server chose before.

        :param bool only_sslv2: If the only available protocol is SSLv2
        """
        log.info("Scanning for cipher suite support")
        if "SSLv2" in self.supported_protocols:
            log.info("Scanning SSLv2 cipher suites")
            self.supported_protocols.remove("SSLv2")
            self.scan_sslv2_cipher_suites()
            if only_sslv2:
                return

        for protocol in self.supported_protocols:
            log.info(f"Scanning {protocol} cipher suites")
            # Ignore TLSv1.1 since the same cipher suites apply for TLSv1.0
            if protocol == "TLSv1.1" and "TLSv1.0" in self.supported_protocols:
                continue

            # Init
            to_test_cipher_suites = ClientHello.get_cipher_suites_for_version(protocol)
            accepted_cipher_suites = bytearray()

            # Skip already tested cipher suites from previous protocol versions if applicable
            for i in range(0, len(self.tested_cipher_suites), 2):
                tested_cipher_suite = self.tested_cipher_suites[i : i + 2]
                cipher_suite_protocols = get_cipher_suite_protocols(tested_cipher_suite)
                if protocol in cipher_suite_protocols:
                    log.debug(
                        f"Found duplicate for {protocol} in other TLS/SSL versions"
                    )
                    to_test_cipher_suites.remove(tested_cipher_suite[0])
                    to_test_cipher_suites.remove(tested_cipher_suite[1])
                    accepted_cipher_suites.extend(tested_cipher_suite)
            client_hello = ClientHello(
                protocol_version_conversion(protocol), to_test_cipher_suites, False
            )
            while True:
                client_hello_bytes = client_hello.pack_client_hello()
                with SafeSocket(self.address, "cipher_suites_scan") as sock:
                    sock.send(client_hello_bytes)
                    sock.shutdown()
                    response = sock.receive()
                if not ClientHello.is_server_hello(response):
                    break
                # Register accepted cipher suite
                cipher_suite_index = to_test_cipher_suites.find(
                    parse_cipher_suite(response)
                )
                cipher_suite = to_test_cipher_suites[
                    cipher_suite_index : cipher_suite_index + 2
                ]
                accepted_cipher_suites.extend(cipher_suite)
                if cipher_suite not in self.tested_cipher_suites:
                    self.tested_cipher_suites.extend(cipher_suite)
                to_test_cipher_suites.pop(cipher_suite_index)
                to_test_cipher_suites.pop(cipher_suite_index)
                client_hello.cipher_suites = client_hello.pack_cipher_suite_bytes(
                    to_test_cipher_suites, False
                )
            # Convert to cipher suite to string
            string_cipher_suites = []
            for i in range(0, len(accepted_cipher_suites), 2):
                string_cipher_suites.append(
                    bytes_to_cipher_suite(accepted_cipher_suites[i : i + 2], "IANA")
                )
            if protocol == "TLSv1.0":
                protocol = "TLSv1.0/TLSv1.1"
            self.unrated.update({protocol: string_cipher_suites})

    def scan_sslv2_cipher_suites(self):
        """
        Scans the available SSLv2 cipher suites

        Since SSLv2 works differently then other SSL/TLS versions
        the server sends his supported cipher suites in the ServerHello
        message.
        """
        sslv2 = SSLv2(self.address)
        sslv2.data = sslv2.connect()
        sslv2.parse_cipher_suite()
        self.unrated.update({"SSLv2": sslv2.server_cipher_suites})

    def rate_cipher_suites(self):
        """
        Rates the supported cipher suites
        """
        if self.unrated is None:
            return
        rated_cipher_suites = {}
        for protocol, protocol_cipher_suites in self.unrated.items():
            for suite in protocol_cipher_suites:
                cipher_suite = CipherSuite(suite)
                cipher_suite.parse_cipher_suite()
                cipher_suite.rate_cipher_suite()
                rated_cipher_suites.update({suite: cipher_suite.rating})
            self.supported.update({protocol: rated_cipher_suites})
            rated_cipher_suites = {}
