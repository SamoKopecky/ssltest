"""Vulnerability test for Forward Secrecy Support"""

from ..VulnerabilityTest import VulnerabilityTest
from ...core.ClientHello import ClientHello
from ...main.utils import send_data_return_sock, is_server_hello, filter_cipher_suite_bytes


class ForwardSecrecySupport(VulnerabilityTest):
    name = 'No Forward Secrecy Support'
    short_name = 'Foward Secrecy'
    description = 'Test for forward secrecy cipher suites'

    def __init__(self, supported_protocols, address, timeout, protocol):
        super().__init__(supported_protocols, address, timeout, protocol)
        self.valid_protocols = ['TLSv1.2', 'TLSv1.1', 'TLSv1.0', 'SSLv3']
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
            cipher_suite_bytes, 'ECDHE|DHE')
        client_hello = ClientHello(
            version, sixty_four_bit_ciphers, False).construct_client_hello()
        response, sock = send_data_return_sock(
            self.address, client_hello, self.timeout, self.name)
        sock.close()
        if is_server_hello(response):
            return False
        else:
            return True
