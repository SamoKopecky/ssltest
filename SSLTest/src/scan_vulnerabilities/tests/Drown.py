from ..VulnerabilityTest import VulnerabilityTest
from ...scan_parameters.connections.ClientHello import ClientHello
from ...scan_parameters.connections.SSLv2 import SSLv2
from ...utils import filter_cipher_suite_bytes, protocol_version_conversion, send_data_return_sock, is_server_hello


class Drown(VulnerabilityTest):
    test_name = 'DROWN'

    def __init__(self, supported_protocols, address, timeout, protocol):
        super().__init__(supported_protocols, address, timeout, protocol)
        self.valid_protocols = ['SSLv3', 'TLSv1.0', 'TLSv1.1', 'TLSv1.2']
        self.scan_once = False
        self.sslv2_tested = False
        self.sslv2_vulnerable = True

    def test(self, version):
        if 'TLSv1.0' in self.supported_protocols and version == 'TLSv1.1':
            return False
        elif 'SSLv2' not in self.supported_protocols or self.supported_protocols == ['SSLv2'] \
                or not self.sslv2_vulnerable:
            return False
        elif not self.sslv2_tested:
            sslv2 = SSLv2(self.address, self.timeout)
            sslv2.send_client_hello()
            sslv2.parse_cipher_suite()
            export_cipher_suites = list(filter(lambda cs: 'EXPORT' in cs, sslv2.server_cipher_suites))
            if len(export_cipher_suites) == 0:
                self.sslv2_vulnerable = False
                return False
            else:
                self.sslv2_tested = True
        # TODO: Test on home server
        # No RSA suites for SSLv2
        cipher_suite_bytes = ClientHello.get_cipher_suites_for_version(protocol_version_conversion(version))
        # All cipher suites that use RSA for kex
        rsa_cipher_suites = filter_cipher_suite_bytes(cipher_suite_bytes, lambda cs: 'TLS_RSA' in cs)
        client_hello = ClientHello(version, rsa_cipher_suites, False)
        client_hello = client_hello.construct_client_hello()
        response, sock = send_data_return_sock(self.address, client_hello, self.timeout, self.test_name)
        sock.close()
        if not is_server_hello(response):
            return False
        return True
