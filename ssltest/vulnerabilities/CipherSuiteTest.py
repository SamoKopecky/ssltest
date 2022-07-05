from abc import ABC

from .VulnerabilityTest import VulnerabilityTest
from ..network.ClientHello import ClientHello
from ..core.utils import filter_cipher_suite_bytes
from ..sockets.SafeSocket import SafeSocket


class CipherSuiteTest(VulnerabilityTest, ABC):
    def __init__(self, supported_protocols, address, protocol):
        super().__init__(supported_protocols, address, protocol)
        self.filter_regex = ""

    def test(self, version):
        """
        Scan the webserver for cipher suite vulnerability

        :param int version: SSL/TLS version
        :return: Whether the server is vulnerable
        :rtype: bool
        """
        cipher_suite_bytes = ClientHello.get_cipher_suites_for_version(version)
        filtered_suites = filter_cipher_suite_bytes(
            cipher_suite_bytes, self.filter_regex
        )
        client_hello = ClientHello(version, filtered_suites, False).pack_client_hello()

        with SafeSocket(self.address, self.usage) as sock:
            sock.send(client_hello)
            response = sock.receive()

        # 0x02 means fatal error and 0x28 means handshake failure
        if not ClientHello.is_server_hello(response) or (
            response[-2] == 0x02 and response[-1] == 0x28
        ):
            return False
        return True
