"""Vulnerability test for Forward Secrecy Support"""

from ..VulnerabilityTest import VulnerabilityTest
from ...network.ClientHello import ClientHello
from ...core.utils import filter_cipher_suite_bytes
from ...sockets.SafeSocket import SafeSocket


class ForwardSecrecySupport(VulnerabilityTest):
    name = "No Forward Secrecy Support"
    short_name = "Forward Secrecy"
    description = "Test for forward secrecy cipher suites"

    def __init__(self, supported_protocols, address, protocol):
        super().__init__(supported_protocols, address, protocol)
        self.valid_protocols = ["TLSv1.2", "TLSv1.1", "TLSv1.0", "SSLv3"]
        self.scan_once = False

    def test(self, version):
        """
        Check if server supports any forward secrecy cipher suites

        :param int version: SSL/TLS version
        :return: Whether the server doesn't support any forward secrecy cipher suites
        :rtype: bool
        """
        cipher_suite_bytes = ClientHello.get_cipher_suites_for_version(version)
        sixty_four_bit_ciphers = filter_cipher_suite_bytes(
            cipher_suite_bytes, "ECDHE|DHE"
        )
        client_hello = ClientHello(
            version, sixty_four_bit_ciphers, False
        ).pack_client_hello()
        with SafeSocket(self.address, self.usage) as sock:
            sock.send(client_hello)
            response = sock.receive()
        if ClientHello.is_server_hello(response):
            return False
        else:
            return True
