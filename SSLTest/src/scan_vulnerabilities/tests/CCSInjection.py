from ..VulnerabilityTest import VulnerabilityTest
from ..ClientHello import ClientHello
from ..utils import is_server_hello
from ...utils import receive_data, send_data_return_sock


class CCSInjection(VulnerabilityTest):
    test_name = 'CCS Injection'

    def __init__(self, supported_protocols, address, timeout):
        super().__init__(supported_protocols, address, timeout)

        self.valid_protocols = ['TLSv1.2', 'TLSv1.1', 'TLSv1.0', 'SSLv3']

    def test(self, version):
        """
        Scan the webserver for CSS injection vulnerability (CVE-2014-0224)

        :param int version: SSL/TLS version
        :return: Whether the server is vulnerable
        :rtype: bool
        """
        client_hello = ClientHello(version).construct_client_hello()
        response, sock = send_data_return_sock(self.address, client_hello, self.timeout, self.test_name)
        if not is_server_hello(response):
            sock.close()
            return False
        sock.send(self.construct_ccs_message(version))
        server_response = receive_data(sock, self.timeout, self.test_name)
        sock.close()
        # No response from server means the CSS message is accepted
        if not server_response:
            return True
        # 0x15 stands for alert message type, 0x0a stands for unexpected message
        if server_response[0] == 0x15 and server_response[6] == 0x0a:
            return False
        return True

    @staticmethod
    def construct_ccs_message(version):
        ccs_message = bytes([
            # Record protocol
            0x14,  # Protocol type (ccs)
            0x03, version,  # Version
            0x00, 0x01,  # Length
            0x01  # CSS message
        ])
        return ccs_message
