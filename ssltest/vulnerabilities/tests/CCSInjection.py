"""Vulnerability test for CCS Injection"""

from ..VulnerabilityTest import VulnerabilityTest
from ...network.ClientHello import ClientHello
from ...sockets.SafeSocket import SafeSocket


class CCSInjection(VulnerabilityTest):
    name = short_name = "CCS Injection"
    description = "Test for Change Cipher Spec injection"

    def __init__(self, supported_protocols, address, protocol):
        super().__init__(supported_protocols, address, protocol)
        self.valid_protocols = ["TLSv1.2", "TLSv1.1", "TLSv1.0", "SSLv3"]

    def test(self, version):
        """
        Scan the webserver for CCS injection vulnerability (CVE-2014-0224)

        :param int version: SSL/TLS version
        :return: Whether the server is vulnerable
        :rtype: bool
        """
        # fmt: off
        ccs_message = bytes([
            # Record protocol
            0x14,  # Protocol type (ccs)
            0x03, version,  # Version
            0x00, 0x01,  # Length
            0x01  # CSS message
        ])
        # fmt: on
        client_hello = ClientHello(version).pack_client_hello()
        with SafeSocket(self.address, self.usage) as sock:
            sock.send(client_hello)
            response = sock.receive()
            if not ClientHello.is_server_hello(response):
                return False
            sock.send(ccs_message)
            response = sock.receive()
        # No response from server means the CSS message is accepted
        if not response:
            return True, "Got no answer from the server"
        # 0x15 stands for alert message type, 0x0a stands for unexpected message
        if response[0] == 0x15 and response[6] == 0x0A:
            return False
        return True
