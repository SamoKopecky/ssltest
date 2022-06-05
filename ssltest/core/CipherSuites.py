import logging

from typing import Tuple

from .CipherSuite import CipherSuite
from .ClientHello import ClientHello
from .SSLv2 import SSLv2
from ..exceptions.ConnectionTimeout import ConnectionTimeout
from ..main.utils import send_data_return_sock, parse_cipher_suite, bytes_to_cipher_suite, protocol_version_conversion, \
    is_server_hello, get_cipher_suite_protocols, Address

log = logging.getLogger(__name__)


class CipherSuites:
    def __init__(self, address, supported_protocols, timeout):
        """
        Constructor

        :param Address address: Webserver address
        :param list supported_protocols: Webserver supported SSL/TLS protocols
        :param int timeout: Timeout
        """
        self.short_timeout = 0.1
        self.timeout = timeout
        self.address = address
        self.supported = {}
        self.unrated = {}
        self.supported_protocols = supported_protocols
        self.tested_cipher_suites = bytearray()

    def scan_cipher_suites(self, only_sslv2):
        """
        Scan the supported cipher suites by the web server

        For each protocol a client hello is sent with all of the
        possible cipher suites. When the server response with a valid
        message a cipher suite chosen by the server is removed from the
        possible cipher suites that the client sends. If the server response
        with an error of some kind the supported cipher suites are those
        which the server chose before.
        """
        log.info('Scanning for cipher suite support')
        if 'SSLv2' in self.supported_protocols:
            log.info('Scanning SSLv2 cipher suites')
            self.supported_protocols.remove('SSLv2')
            self.scan_sslv2_cipher_suites()
            if only_sslv2:
                return

        for protocol in self.supported_protocols:
            log.info(f'Scanning {protocol} cipher suites')
            # Ignore TLSv1.1 since the same cipher suites apply for TLSv1.0
            if protocol == 'TLSv1.1' and 'TLSv1.0' in self.supported_protocols:
                continue

            # Init
            to_test_cipher_suites = ClientHello.get_cipher_suites_for_version(
                protocol)
            accepted_cipher_suites = bytearray()

            # Skip already tested cipher suites from previous protocol versions if applicable
            for i in range(0, len(self.tested_cipher_suites), 2):
                tested_cipher_suite = self.tested_cipher_suites[i: i + 2]
                cipher_suite_protocols = get_cipher_suite_protocols(
                    tested_cipher_suite)
                if protocol in cipher_suite_protocols:
                    to_test_cipher_suites.remove(tested_cipher_suite[0])
                    to_test_cipher_suites.remove(tested_cipher_suite[1])
                    accepted_cipher_suites.extend(tested_cipher_suite)
            client_hello = ClientHello(protocol_version_conversion(protocol),
                                       to_test_cipher_suites, False)
            while True:
                client_hello_bytes = client_hello.construct_client_hello()
                response, try_again = self.try_receive_data(
                    client_hello_bytes, protocol)
                if try_again:
                    continue
                if not is_server_hello(response):
                    break
                # Register accepted cipher suite
                cipher_suite_index = to_test_cipher_suites.find(
                    parse_cipher_suite(response))
                cipher_suite = to_test_cipher_suites[cipher_suite_index: cipher_suite_index + 2]
                accepted_cipher_suites.extend(cipher_suite)
                if cipher_suite not in self.tested_cipher_suites:
                    self.tested_cipher_suites.extend(cipher_suite)
                to_test_cipher_suites.pop(cipher_suite_index)
                to_test_cipher_suites.pop(cipher_suite_index)
                client_hello.cipher_suites = client_hello.pack_cipher_suite_bytes(
                    to_test_cipher_suites, False
                )
            # Convert to cipher suite to string
            string_cipher_suites = []
            for i in range(0, len(accepted_cipher_suites), 2):
                string_cipher_suites.append(bytes_to_cipher_suite(
                    accepted_cipher_suites[i:i + 2], 'IANA'))
            if protocol == 'TLSv1.0':
                protocol = 'TLSv1.0/TLSv1.1'
            self.unrated.update({protocol: string_cipher_suites})

    def try_receive_data(self, client_hello_bytes, protocol):
        """
        Try to receive the response of the sent client hello

        If the server can't keep up or it resets the connection, slow down

        :param bytes or bytearray client_hello_bytes: client hello msg
        :param str protocol: SSL/TLS protocol
        :return: The server response and whether to try again
        :rtype: Tuple[bytes, bool]
        """
        if self.short_timeout >= 1:
            raise ConnectionTimeout
        try:
            response, sock = send_data_return_sock(self.address, client_hello_bytes, self.short_timeout,
                                                   f'cipher_suite_scanning_for_{protocol}')
            sock.close()
        except ConnectionTimeout:
            log.warning('Connection timed out, increasing timeout by 0.1s')
            self.short_timeout += 0.1
            return bytes(), True
        if len(response) == 0:
            log.warning('No received data, increasing timeout by 0.1s')
            self.short_timeout += 0.1
            return bytes(), True
        return response, False

    def scan_sslv2_cipher_suites(self):
        """
        Scans the available SSLv2 cipher suites

        Since SSLv2 works differently then other SSL/TLS versions
        the server sends his supported cipher suites in the ServerHello
        message.
        """
        sslv2 = SSLv2(self.address, self.timeout)
        sslv2.send_client_hello()
        sslv2.parse_cipher_suite()
        self.unrated.update({'SSLv2': sslv2.server_cipher_suites})

    def rate_cipher_suites(self):
        """
        Rates the supported cipher suites
        """
        if self.unrated is None:
            return
        rated_cipher_suites = {}
        for protocol, protocol_cipher_suites in self.unrated.items():
            for suite in protocol_cipher_suites:
                cipher_suite = CipherSuite(suite)
                cipher_suite.parse_cipher_suite()
                cipher_suite.rate_cipher_suite()
                rated_cipher_suites.update({suite: cipher_suite.rating})
            self.supported.update({protocol: rated_cipher_suites})
            rated_cipher_suites = {}
