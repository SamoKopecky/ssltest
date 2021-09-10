from ..VulnerabilityTest import VulnerabilityTest
from ..ClientHello import ClientHello
from ..utils import is_server_hello
from ...utils import communicate_data_return_sock


class InsecureRenegotiation(VulnerabilityTest):
    test_name = 'Insecure Renegotiation'

    def __init__(self, supported_protocols, address):
        super().__init__(supported_protocols, address)
        self.valid_protocols = ['TLSv1.2', 'TLSv1.1', 'TLSv1.0', 'SSLv3']
        self.renegotiation_extension = bytes([
            # Secure renegotiation extension
            0xff, 0x01, 0x00, 0x01, 0x00
        ])

    def test(self, version):
        """
        Scan the webserver for insecure renegotiation (CVE-2009-3555)

        :param int version: SSL/TLS version
        :return: Whether the server is vulnerable
        :rtype: bool
        """
        client_hello = ClientHello(version)
        client_hello.extensions += self.renegotiation_extension
        client_hello = client_hello.construct_client_hello()
        response, sock = communicate_data_return_sock(self.address, client_hello, self.timeout, self.test_name)
        sock.close()
        if not is_server_hello(response):
            return False
        # If there is no renegotiation info found it means the server doesn't
        # support secure renegotiation extension
        renegotiation_info = response.find(self.renegotiation_extension)
        # -1 means no match
        if renegotiation_info == -1:
            return True
        return False
