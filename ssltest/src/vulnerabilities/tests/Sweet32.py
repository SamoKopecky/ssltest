"""Vulnerability test for SWEET 32"""

from ..VulnerabilityTest import VulnerabilityTest
from ...core.ClientHello import ClientHello
from ...main.utils import send_data_return_sock, is_server_hello, filter_cipher_suite_bytes


class Sweet32(VulnerabilityTest):
    name = short_name = 'SWEET32'
    description = 'Test support for 64-bit key length encryption'

    def __init__(self, supported_protocols, address, timeout, protocol):
        super().__init__(supported_protocols, address, timeout, protocol)
        self.valid_protocols = ['TLSv1.2', 'TLSv1.1', 'TLSv1.0', 'SSLv3']
        self.scan_once = False

    def test(self, version):
        """
        Scan for SWEET32 vulnerability (CVE-2016-2183)

        :param int version: SSL/TLS version
        :return: Whether the server is vulnerable
        :rtype: bool
        """
        cipher_suite_bytes = ClientHello.get_cipher_suites_for_version(version)
        sixty_four_bit_ciphers = filter_cipher_suite_bytes(
            cipher_suite_bytes, 'DES')
        client_hello = ClientHello(
            version, sixty_four_bit_ciphers, False).construct_client_hello()
        response, sock = send_data_return_sock(
            self.address, client_hello, self.timeout, self.name)
        sock.close()
        if not is_server_hello(response):
            return False
        # 0x02 means fatal error and 0x28 means handshake failure
        if response[-2] == 0x02 and response[-1] == 0x28:
            return False
        else:
            return True
