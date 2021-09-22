import logging

from .CipherSuite import CipherSuite
from ..connections.ClientHello import ClientHello
from ...utils import send_data_return_sock, parse_cipher_suite, bytes_to_cipher_suite
from ...scan_vulnerabilities.utils import protocol_version_conversion, is_server_hello


class CipherSuites:
    def __init__(self, address, supported_protocols):
        self.timeout = 0.3
        self.address = address
        self.supported_cipher_suites = {}
        self.supported_protocols = supported_protocols

    def scan_cipher_suites(self):
        logging.info('scanning cipher suite support')
        if 'SSLv2' in self.supported_protocols:
            self.supported_protocols.remove('SSLv2')
        for protocol in self.supported_protocols:
            # Ignore TLSv1.1 since the cipher suites apply for TLSv1.0
            if protocol == 'TLSv1.1' and 'TLSv1.0' in self.supported_protocols:
                continue
            test_cipher_suites = ClientHello.get_cipher_suites_for_version(protocol)
            accepted_cipher_suites = bytearray([])
            client_hello = ClientHello(protocol_version_conversion(protocol, True), test_cipher_suites, False)
            while True:
                client_hello_bytes = client_hello.construct_client_hello()
                debug_msg = f'cipher_suite_scanning_for_{protocol}'
                response, sock = send_data_return_sock(self.address, client_hello_bytes, self.timeout, debug_msg)
                sock.close()
                if not is_server_hello(response):
                    break
                cipher_suite_index = test_cipher_suites.find(parse_cipher_suite(response))
                accepted_cipher_suites.extend(test_cipher_suites[cipher_suite_index: cipher_suite_index + 2])
                test_cipher_suites.pop(cipher_suite_index)
                test_cipher_suites.pop(cipher_suite_index)
                client_hello.cipher_suites = client_hello.pack_cipher_suite_bytes(
                    test_cipher_suites, False
                )
            string_cipher_suites = []
            for i in range(0, len(accepted_cipher_suites), 2):
                string_cipher_suites.append(bytes_to_cipher_suite(accepted_cipher_suites[i:i + 2], 'IANA'))
            if protocol == 'TLSv1.0':
                protocol = 'TLSv1.0/TLSv1.1'
            rated_cipher_suites = self.rate_cipher_suites(string_cipher_suites)
            self.supported_cipher_suites.update({protocol: rated_cipher_suites})

    @staticmethod
    def rate_cipher_suites(string_cipher_suites):
        rated_cipher_suites = {}
        for suite in string_cipher_suites:
            cipher_suite = CipherSuite(suite)
            cipher_suite.parse_cipher_suite()
            cipher_suite.rate_cipher_suite()
            rated_cipher_suites.update({suite: cipher_suite.rating})
        return rated_cipher_suites
