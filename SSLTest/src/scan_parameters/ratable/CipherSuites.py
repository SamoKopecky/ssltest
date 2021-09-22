import logging

from .CipherSuite import CipherSuite
from ..connections.ClientHello import ClientHello
from ..connections.SSLv2 import SSLv2
from ...utils import send_data_return_sock, parse_cipher_suite, bytes_to_cipher_suite
from ...scan_vulnerabilities.utils import protocol_version_conversion, is_server_hello


class CipherSuites:
    def __init__(self, address, supported_protocols, timeout):
        self.cipher_suite_scan_timeout = 0.1
        self.timeout = timeout
        self.address = address
        self.supported_cipher_suites = {}
        self.unrated_cipher_suites = {}
        self.supported_protocols = supported_protocols

    def scan_cipher_suites(self):
        """
        Scan the supported cipher suites by the web server

        For each protocol a client hello is sent with all of the
        possible cipher suites. When the server response with a valid
        message like ServerHello a cipher suite chosen by the server is
        removed from the possible cipher suites that the client sends.
        If the server response with an error of some kind the supported cipher
        suites are those which the server chose before.
        """
        logging.info('scanning cipher suite support')
        if 'SSLv2' in self.supported_protocols:
            self.supported_protocols.remove('SSLv2')
            self.scan_sslv2_cipher_suites()
        for protocol in self.supported_protocols:
            # Ignore TLSv1.1 since the same cipher suites apply for TLSv1.0
            if protocol == 'TLSv1.1' and 'TLSv1.0' in self.supported_protocols:
                continue
            test_cipher_suites = ClientHello.get_cipher_suites_for_version(protocol)
            accepted_cipher_suites = bytearray([])
            client_hello = ClientHello(protocol_version_conversion(protocol, True), test_cipher_suites, False)
            while True:
                client_hello_bytes = client_hello.construct_client_hello()
                debug_msg = f'cipher_suite_scanning_for_{protocol}'
                response, sock = send_data_return_sock(self.address, client_hello_bytes, self.cipher_suite_scan_timeout,
                                                       debug_msg)
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
            self.unrated_cipher_suites.update({protocol: string_cipher_suites})

    def scan_sslv2_cipher_suites(self):
        """
        Scans the available SSLv2 cipher suites

        Since SSLv2 works differently then other SSL/TLS versions
        the server sends his supported cipher suites in the ServerHello
        message.
        """
        logging.debug('cipher_suite_scanning_for_SSLv2}')
        sslv2 = SSLv2(self.address[0], self.address[1], self.timeout)
        sslv2.send_client_hello()
        sslv2.parse_cipher_suite()
        self.unrated_cipher_suites.update({'SSLv2': sslv2.server_cipher_suites})

    def rate_cipher_suites(self):
        """
        Rates the supported cipher suites
        """
        if self.unrated_cipher_suites is None:
            return
        rated_cipher_suites = {}
        for protocol, protocol_cipher_suites in self.unrated_cipher_suites.items():
            for suite in protocol_cipher_suites:
                cipher_suite = CipherSuite(suite)
                cipher_suite.parse_cipher_suite()
                cipher_suite.rate_cipher_suite()
                rated_cipher_suites.update({suite: cipher_suite.rating})
            self.supported_cipher_suites.update({protocol: rated_cipher_suites})
            rated_cipher_suites = {}
