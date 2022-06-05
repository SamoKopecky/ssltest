"""Vulnerability test for Insecure Renegotiation"""

from ..VulnerabilityTest import VulnerabilityTest
from ...core.ClientHello import ClientHello
from ...main.utils import send_data_return_sock, is_server_hello


class InsecureRenegotiation(VulnerabilityTest):
    name = 'Insecure Renegotiation'
    short_name = 'Renegotiation'
    description = 'Test for insecure renegotiation (secure renegotiation extension)'

    def __init__(self, supported_protocols, address, timeout, protocol):
        super().__init__(supported_protocols, address, timeout, protocol)
        self.valid_protocols = ['TLSv1.2', 'TLSv1.1', 'TLSv1.0', 'SSLv3']
        self.renegotiation_extension = bytes([
            # Secure renegotiation extension
            0xff, 0x01, 0x00, 0x01, 0x00
        ])

    def test(self, version):
        """
        Scan the webserver for insecure renegotiation (CVE-2009-3555)

        :param int version: SSL/TLS version
        :return: Whether the server is vulnerable
        :rtype: bool
        """
        client_hello = ClientHello(version)
        client_hello.extensions += self.renegotiation_extension
        client_hello = client_hello.construct_client_hello()
        response, sock = send_data_return_sock(
            self.address, client_hello, self.timeout, self.name)
        sock.close()
        if not is_server_hello(response):
            return False
        # If there is no renegotiation info found it means the server doesn't
        # support secure renegotiation extension
        renegotiation_info = response.find(self.renegotiation_extension)
        # -1 means no match
        if renegotiation_info == -1:
            return True
        return False
