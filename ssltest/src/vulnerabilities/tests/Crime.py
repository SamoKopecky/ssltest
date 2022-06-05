"""Vulnerability test for CRIME"""

from ..VulnerabilityTest import VulnerabilityTest
from ...core.ClientHello import ClientHello
from ...main.utils import send_data_return_sock, is_server_hello


class Crime(VulnerabilityTest):
    name = short_name = 'CRIME'
    description = 'Test for ssl/tls encoding methods'

    def __init__(self, supported_protocols, address, timeout, protocol):
        super().__init__(supported_protocols, address, timeout, protocol)
        self.valid_protocols = ['TLSv1.2', 'TLSv1.1', 'TLSv1.0', 'SSLv3']

    def test(self, version):
        """
        Scan for CRIME vulnerability (CVE-2012-4929)

        :param int version: SSL/TLS version
        :return: Whether the server is vulnerable
        :rtype: bool
        """
        client_hello = ClientHello(version)
        client_hello.compression = bytearray([
            0x01,  # Compression method length
            0x01  # Compression method (deflate)
        ])
        client_hello = client_hello.construct_client_hello()
        response, sock = send_data_return_sock(
            self.address, client_hello, self.timeout, self.name)
        sock.close()
        if not is_server_hello(response):
            return False
        elif response[-2] == 0x02:  # 0x02 stands for fatal error
            return False
        else:
            return True
