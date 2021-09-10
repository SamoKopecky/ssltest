from ..VulnerabilityTest import VulnerabilityTest
from ..ClientHello import ClientHello
from ..utils import is_server_hello
from ...utils import communicate_data_return_sock


class RC4Support(VulnerabilityTest):
    test_name = 'RC4 Support'

    def __init__(self, supported_protocols, address):
        super().__init__(supported_protocols, address)
        self.valid_protocols = ['TLSv1.2', 'TLSv1.1', 'TLSv1.0', 'SSLv3']

    def test(self, version):
        """
        Scan for rc4 cipher support

        :param int version: SSL/TLS version
        :return: Whether the server is vulnerable
        :rtype: bool
        """
        rc4_ciphers = bytearray([
            0x00, 0x24,  # Cipher suites length
            # Only RC4 Cipher suites
            0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x17,
            0x00, 0x18, 0x00, 0x20, 0x00, 0x24, 0x00, 0x28,
            0x00, 0x2B, 0x00, 0x8A, 0x00, 0x8E, 0x00, 0x92,
            0xC0, 0x02, 0xC0, 0x07, 0xC0, 0x0C, 0xC0, 0x11,
            0xC0, 0x16, 0xC0, 0x33
        ])
        client_hello = ClientHello(version, rc4_ciphers).construct_client_hello()
        response, sock = communicate_data_return_sock(self.address, client_hello, self.timeout, self.test_name)
        sock.close()
        if not is_server_hello(response):
            return False
        # 0x02 means fatal error and 0x28 means handshake failure
        if response[-2] == 0x02 and response[-1] == 0x28:
            return False
        else:
            return True
