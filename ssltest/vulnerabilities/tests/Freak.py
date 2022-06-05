"""Vulnerability test for FREAK vulnerability"""

from ..VulnerabilityTest import VulnerabilityTest
from ...core.ClientHello import ClientHello
from ...main.utils import filter_cipher_suite_bytes, send_data_return_sock, is_server_hello


class Freak(VulnerabilityTest):
    name = short_name = 'FREAK'
    description = 'Test for RSA + EXPORT cipher suites'

    def __init__(self, supported_protocols, address, timeout, protocol):
        super().__init__(supported_protocols, address, timeout, protocol)
        self.valid_protocols = ['TLSv1.2', 'TLSv1.1', 'TLSv1.0', 'SSLv3']
        self.scan_once = False

    def test(self, version):
        cipher_suite_bytes = ClientHello.get_cipher_suites_for_version(version)
        rsa_export_cipher_suites = filter_cipher_suite_bytes(
            cipher_suite_bytes, 'RSA.*EXPORT')
        client_hello = ClientHello(
            version, rsa_export_cipher_suites, False).construct_client_hello()
        response, sock = send_data_return_sock(
            self.address, client_hello, self.timeout, self.name)
        sock.close()
        if is_server_hello(response):
            return True
        else:
            return False
