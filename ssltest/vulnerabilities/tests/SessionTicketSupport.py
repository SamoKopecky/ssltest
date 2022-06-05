"""Vulnerability test for Session Ticker Support"""

from ..VulnerabilityTest import VulnerabilityTest
from ...core.ClientHello import ClientHello
from ...main.utils import send_data_return_sock, is_server_hello


class SessionTicketSupport(VulnerabilityTest):
    name = 'Session Ticket Support'
    short_name = 'Session Ticket'
    description = 'Test for session ticket support'

    def __init__(self, supported_protocols, address, timeout, protocol):
        super().__init__(supported_protocols, address, timeout, protocol)
        self.valid_protocols = ['TLSv1.2', 'TLSv1.1', 'TLSv1.0', 'SSLv3']
        self.session_ticket_extension = bytes([
            # Session ticket
            0x00, 0x23, 0x00, 0x00
        ])

    def test(self, version):
        """
        Scan for session ticket support vulnerability

        :param int version: SSL/TLS version
        :return: Whether the server is vulnerable
        :rtype: bool
        """
        client_hello = ClientHello(version)
        client_hello.extensions += self.session_ticket_extension
        client_hello = client_hello.construct_client_hello()
        response, sock = send_data_return_sock(
            self.address, client_hello, self.timeout, self.name)
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
