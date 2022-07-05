"""Vulnerability test for CRIME"""

from ..VulnerabilityTest import VulnerabilityTest
from ...network.ClientHello import ClientHello
from ...sockets.SafeSocket import SafeSocket


class Crime(VulnerabilityTest):
    name = short_name = "CRIME"
    description = "Test for ssl/tls encoding methods"

    def __init__(self, supported_protocols, address, protocol):
        super().__init__(supported_protocols, address, protocol)
        self.valid_protocols = ["TLSv1.2", "TLSv1.1", "TLSv1.0", "SSLv3"]

    def test(self, version):
        """
        Scan for CRIME vulnerability (CVE-2012-4929)

        :param int version: SSL/TLS version
        :return: Whether the server is vulnerable
        :rtype: bool
        """
        with SafeSocket(self.address, self.usage) as sock:
            client_hello = ClientHello(version)
            client_hello.compression = bytearray(
                [
                    0x01,  # Compression method length
                    0x01,  # Compression method (deflate)
                ]
            )
            sock.send(client_hello.pack_client_hello())
            response = sock.receive()
        if not ClientHello.is_server_hello(response):
            return False
        elif response[-2] == 0x02:  # 0x02 stands for fatal error
            return False
        else:
            return True
