"""Vulnerability test for Heartbleed"""

from ..VulnerabilityTest import VulnerabilityTest
from ...core.ClientHello import ClientHello
from ...main.utils import receive_data, send_data_return_sock, is_server_hello


class Heartbleed(VulnerabilityTest):
    name = short_name = 'Heartbleed'
    description = 'Test for Heartbleed vulnerability'

    def __init__(self, supported_protocols, address, timeout, protocol):
        super().__init__(supported_protocols, address, timeout, protocol)
        self.valid_protocols = ['TLSv1.2', 'TLSv1.1', 'TLSv1.0', 'SSLv3']

    def test(self, version):
        """
        Scan for heartbleed vulnerability

        :param int version: SSL/TLS version
        :return: Whether the server is vulnerable
        :rtype: bool
        """
        heartbeat_extension = bytearray([0x00, 0x0f, 0x00, 0x01, 0x01])
        client_hello = ClientHello(version)
        client_hello.extensions += heartbeat_extension
        response, sock = send_data_return_sock(self.address, client_hello.construct_client_hello(),
                                               self.timeout, self.name)
        if not is_server_hello(response):
            sock.close()
            return False
        sock.send(self.construct_heartbeat_request(version))
        heartbeat_response = receive_data(sock, self.timeout, self.name)
        sock.close()
        # Server ignores heartbeat request
        if not heartbeat_response:
            return False
        # Heartbeat content type in record protocol
        elif heartbeat_response[0] == 0x18:
            return True
        return False

    @staticmethod
    def construct_heartbeat_request(version):
        heartbeat_request = bytes([
            # Record protocol
            0x18,  # Content type (Handshake)
            0x03, version,  # Version
            0x00, 0x03,  # Length
            # Heartbeat
            0x01,  # Type (Request)
            0x40, 0x00,  # Payload length
        ])
        return heartbeat_request
