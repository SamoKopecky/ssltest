from ..VulnerabilityTest import VulnerabilityTest
from ..ClientHello import ClientHello
from ...scan_parameters.connections.SSLv2 import SSLv2


class Drown(VulnerabilityTest):
    test_name = 'DROWN'

    def __init__(self, supported_protocols, address):
        super().__init__(supported_protocols, address)
        self.valid_protocols = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1', 'TLSv1.2']

    def test(self, version):
        if 'SSLv2' not in self.supported_protocols:
            return False
        elif self.supported_protocols == ['SSLv2']:
            return False
        sslv2 = SSLv2(self.address[0], self.address[1])
        sslv2.send_client_hello()
        sslv2.parse_cipher_suite()
        export_cipher_suites = list(filter(lambda cs: 'EXPORT' in cs, sslv2.server_cipher_suites))
        if len(export_cipher_suites) == 0:
            return False
        # TODO: Add RSA cipher suite checking when all cipher suite scanning is added
        return True
