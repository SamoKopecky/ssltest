from ..VulnerabilityTest import VulnerabilityTest
from ...scan_parameters.connections.ClientHello import ClientHello
from ...utils import send_data_return_sock, is_server_hello, filter_cipher_suite_bytes


class ForwardSecrecySupport(VulnerabilityTest):
    test_name = "No Forward Secrecy Support"

    def __init__(self, supported_protocols, address, timeout, protocol):
        super().__init__(supported_protocols, address, timeout, protocol)
        self.valid_protocols = ['TLSv1.2', 'TLSv1.1', 'TLSv1.0', 'SSLv3']
        self.scan_once = False

    def test(self, version):
        if 'TLSv1.0' in self.supported_protocols and version == 'TLSv1.1':
            return False
        cipher_suite_bytes = ClientHello.get_cipher_suites_for_version(version)
        sixty_four_bit_ciphers = filter_cipher_suite_bytes(cipher_suite_bytes, lambda cs: 'ECDHE' in cs or 'DHE' in cs)
        client_hello = ClientHello(version, sixty_four_bit_ciphers, False).construct_client_hello()
        response, sock = send_data_return_sock(self.address, client_hello, self.timeout, self.test_name)
        sock.close()
        if is_server_hello(response):
            return False
        else:
            return True
