from ..VulnerabilityTest import VulnerabilityTest
from ..utils import is_server_hello
from ...utils import send_data_return_sock
from ...scan_parameters.connections.ClientHello import ClientHello


class SessionTicketSupport(VulnerabilityTest):
    test_name = 'Session Ticket Support'

    def __init__(self, supported_protocols, address, timeout):
        super().__init__(supported_protocols, address, timeout)
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
        response, sock = send_data_return_sock(self.address, client_hello, self.timeout, self.test_name)
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
