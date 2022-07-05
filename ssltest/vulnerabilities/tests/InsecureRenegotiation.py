"""Vulnerability test for Insecure Renegotiation"""

from ..VulnerabilityTest import VulnerabilityTest
from ...network.ClientHello import ClientHello
from ...sockets.SafeSocket import SafeSocket


class InsecureRenegotiation(VulnerabilityTest):
    name = "Insecure Renegotiation"
    short_name = "Renegotiation"
    description = "Test for insecure renegotiation (secure renegotiation extension)"

    def __init__(self, supported_protocols, address, protocol):
        super().__init__(supported_protocols, address, protocol)
        self.valid_protocols = ["TLSv1.2", "TLSv1.1", "TLSv1.0", "SSLv3"]
        # fmt: off
        self.renegotiation_extension = bytes([
            # Secure renegotiation extension
            0xff, 0x01, 0x00, 0x01, 0x00
        ])
        # fmt: on

    def test(self, version):
        """
        Scan the webserver for insecure renegotiation (CVE-2009-3555)

        :param int version: SSL/TLS version
        :return: Whether the server is vulnerable
        :rtype: bool
        """
        client_hello = ClientHello(version)
        client_hello.extensions += self.renegotiation_extension
        client_hello = client_hello.pack_client_hello()

        with SafeSocket(self.address, self.usage) as sock:
            sock.send(client_hello)
            response = sock.receive()

        if not ClientHello.is_server_hello(response):
            return False
        # If there is no renegotiation info found it means the server doesn't
        # support secure renegotiation extension
        renegotiation_info = response.find(self.renegotiation_extension)
        # -1 means no match
        if renegotiation_info == -1:
            return True
        return False
