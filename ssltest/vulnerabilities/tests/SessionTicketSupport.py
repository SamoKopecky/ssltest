"""Vulnerability test for Session Ticker Support"""

from ..VulnerabilityTest import VulnerabilityTest
from ...network.ClientHello import ClientHello
from ...sockets.SafeSocket import SafeSocket


class SessionTicketSupport(VulnerabilityTest):
    name = "Session Ticket Support"
    short_name = "Session Ticket"
    description = "Test for session ticket support"

    def __init__(self, supported_protocols, address, protocol):
        super().__init__(supported_protocols, address, protocol)
        self.valid_protocols = ["TLSv1.2", "TLSv1.1", "TLSv1.0", "SSLv3"]
        # fmt: off
        self.session_ticket_extension = bytes([
            # Session ticket
            0x00, 0x23, 0x00, 0x00
        ])
        # fmt: on

    def test(self, version):
        """
        Scan for session ticket support vulnerability

        :param int version: SSL/TLS version
        :return: Whether the server is vulnerable
        :rtype: bool
        """
        client_hello = ClientHello(version)
        client_hello.extensions += self.session_ticket_extension
        client_hello = client_hello.pack_client_hello()

        with SafeSocket(self.address, self.usage) as sock:
            sock.send(client_hello)
            response = sock.receive()

        if not ClientHello.is_server_hello(response):
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
        return True
