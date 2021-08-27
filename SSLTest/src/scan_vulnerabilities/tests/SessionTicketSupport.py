from ..VulnerabilityTest import VulnerabilityTest
from ..utils import is_server_hello
from ...utils import communicate_data_return_sock


class SessionTicketSupport(VulnerabilityTest):
    def __init__(self, supported_protocols, address):
        super().__init__(supported_protocols, address)
        self.test_name = 'Session Ticket Support'
        self.valid_protocols = ['TLSv1.2']
        self.session_ticket_extension = bytes([
            0x00, 0x23, 0x00, 0x00
        ])

    def test(self, version):
        """
        Scan for session ticket support vulnerability

        :param int version: SSL/TLS version
        :return: Whether the server is vulnerable
        :rtype: bool
        """
        client_hello = self.construct_client_hello(version)
        response, sock = communicate_data_return_sock(self.address, client_hello, self.timeout, self.test_name)
        sock.close()
        if not is_server_hello(response):
            return False
        # If there is no session ticket found it means the server doesn't
        # support session ticket extension
        session_ticket = response.find(self.session_ticket_extension)
        # If the server sends a fatal alert message
        if response[-2] == 0x02:
            return False
        # -1 means no match
        elif session_ticket == -1:
            return False
        else:
            return True

    @staticmethod
    def construct_client_hello(version):
        """
        Construct the client hello for the specific vulnerability

        :param int version: SSL/TLS version
        :return: client hello
        :rtype: bytes
        """
        client_hello = bytes([
            # Record protocol
            0x16,  # Content type (Handshake)
            0x03, version,  # Version
            0x00, 0xcd,  # Length
            # Handshake protocol
            0x01,  # Handshake type
            0x00, 0x00, 0xc9,  # Length
            0x03, version,  # TLS version
            # Random bytes
            0xf0, 0x36, 0x90, 0x63, 0x5a, 0x8c, 0xea, 0xaf,
            0xc5, 0x30, 0xcc, 0x46, 0x37, 0x8d, 0x95, 0x87,
            0x25, 0xff, 0xa6, 0xf2, 0x68, 0xa1, 0x51, 0xe8,
            0x2e, 0x2c, 0x7e, 0x6f, 0xd4, 0xaf, 0x05, 0xa2,
            0x20,  # Session id length
            # Session ID
            0x1a, 0xfb, 0x28, 0xdd, 0x4e, 0x50, 0x0d, 0xdf,
            0x0c, 0xe1, 0xa3, 0xd6, 0x8c, 0x9d, 0x59, 0x7b,
            0x09, 0xd0, 0x67, 0x94, 0x29, 0x92, 0x1e, 0xbd,
            0x72, 0x0b, 0x42, 0xec, 0x00, 0x44, 0x27, 0x73,
            0x00, 0x3e,  # Cipher suites length
            # Cipher suites
            0x13, 0x02, 0x13, 0x03, 0x13, 0x01, 0xc0, 0x2c,
            0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8,
            0xcc, 0xaa, 0xc0, 0x2b, 0xc0, 0x2f, 0x00, 0x9e,
            0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23,
            0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a, 0xc0, 0x14,
            0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33,
            0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d, 0x00, 0x3c,
            0x00, 0x35, 0x00, 0x2f, 0x00, 0xff,
            0x01,  # Compression method length
            0x00,  # Compression method
            0x00, 0x42,  # Extension length
            # Supported groups
            0x00, 0x0a, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x1d,
            0x00, 0x17, 0x00, 0x1e, 0x00, 0x19, 0x00, 0x18,
            # Session ticket
            0x00, 0x23, 0x00, 0x00,
            # Signature algorithm
            0x00, 0x0d, 0x00, 0x2a, 0x00, 0x28, 0x04, 0x03,
            0x05, 0x03, 0x06, 0x03, 0x08, 0x07, 0x08, 0x08,
            0x08, 0x09, 0x08, 0x0a, 0x08, 0x0b, 0x08, 0x04,
            0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01,
            0x06, 0x01, 0x03, 0x03, 0x03, 0x01, 0x03, 0x02,
            0x04, 0x02, 0x05, 0x02, 0x06, 0x02
        ])
        return client_hello
