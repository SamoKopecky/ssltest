from ...scan_vulnerabilities.ClientHello import ClientHello
from ...utils import send_data_return_sock, parse_cipher_suite, bytes_to_cipher_suite
from ...scan_vulnerabilities.utils import version_conversion, is_server_hello


class CipherSuites:
    def __init__(self, address, supported_protocols):
        self.timeout = 2
        self.address = address
        self.supported_ciphers = {}
        self.supported_protocols = supported_protocols

    def scan_cipher_suites(self):
        if 'SSLv2' in self.supported_protocols:
            self.supported_protocols.remove('SSLv2')
        for protocol in self.supported_protocols:
            if protocol == 'TLSv1.1' and 'TLSv1.0' in self.supported_protocols:
                continue
            test_ciphers = ClientHello.get_cipher_suites_for_version(protocol)
            good_ciphers = bytearray([])
            while True:
                client_hello = ClientHello(version_conversion(protocol, True), test_ciphers,
                                           False).construct_client_hello()
                response, sock = send_data_return_sock(self.address, client_hello, 1,
                                                       'cipher_suite_scanning')
                sock.close()
                if not is_server_hello(response):
                    break
                cipher_suite = parse_cipher_suite(response)
                index = test_ciphers.find(cipher_suite)
                good_ciphers.extend(test_ciphers[index: index + 2])
                # TODO: do this better
                test_ciphers.pop(index)
                test_ciphers.pop(index)
            string_ciphers = []
            rated_ciphers = {}
            for i in range(0, len(good_ciphers), 2):
                string_ciphers.append(bytes_to_cipher_suite(good_ciphers[i:i + 2], 'IANA'))
            for cipher in string_ciphers:
                rated_ciphers.update({cipher: 1})
            if protocol == 'TLSv1.0':
                protocol = 'TLSv1.0/TLSv1.1'
            self.supported_ciphers.update({protocol: rated_ciphers})
