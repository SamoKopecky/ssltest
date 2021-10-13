from ..VulnerabilityTest import VulnerabilityTest
from ...scan_parameters.connections.ClientHello import ClientHello
from ...scan_parameters.connections.SSLv2 import SSLv2
from ...utils import filter_cipher_suite_bytes, send_data_return_sock, is_server_hello


class Drown(VulnerabilityTest):
    test_name = 'DROWN'

    def __init__(self, supported_protocols, address, timeout, protocol):
        super().__init__(supported_protocols, address, timeout, protocol)
        self.valid_protocols = ['SSLv3', 'TLSv1.0', 'TLSv1.1', 'TLSv1.2']
        self.scan_once = False
        self.sslv2_vulnerable = True

    def test(self, version):
        """
        Scan for DROWN vulnerability (CVE-2016-0800)

        :param int version: SSL/TLS version
        :return: Whether the server is vulnerable
        :rtype: bool
        """
        if 'SSLv2' not in self.supported_protocols or self.supported_protocols == ['SSLv2'] \
                or not self.sslv2_vulnerable:
            return False
        cipher_suite_bytes = ClientHello.get_cipher_suites_for_version(version)
        # All cipher suites that use RSA for kex
        rsa_cipher_suites = filter_cipher_suite_bytes(cipher_suite_bytes, lambda cs: 'TLS_RSA' in cs)
        client_hello = ClientHello(version, rsa_cipher_suites, False)
        client_hello = client_hello.construct_client_hello()
        response, sock = send_data_return_sock(self.address, client_hello, self.timeout, self.test_name)
        sock.close()
        if not is_server_hello(response):
            return False
        return True

    def run_once(self):
        """
        Scan for the EXPORT cipher suites in SSLv2 support
        """
        if 'SSLv2' not in self.supported_protocols:
            return
        sslv2 = SSLv2(self.address, self.timeout)
        sslv2.send_client_hello()
        sslv2.parse_cipher_suite()
        export_cipher_suites = list(filter(lambda cs: 'EXPORT' in cs, sslv2.server_cipher_suites))
        if len(export_cipher_suites) == 0:
            self.sslv2_vulnerable = False