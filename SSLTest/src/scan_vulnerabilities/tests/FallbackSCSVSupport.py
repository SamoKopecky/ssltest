from ..VulnerabilityTest import VulnerabilityTest, version_conversion
from ..ClientHello import ClientHello
from ..utils import is_server_hello
from ...utils import send_data_return_sock


class FallbackSCSVSupport(VulnerabilityTest):
    test_name = 'No Fallback SCSV Support'

    def __init__(self, supported_protocols, address):
        super().__init__(supported_protocols, address)
        self.valid_protocols = ['TLSv1.2', 'TLSv1.1', 'TLSv1.0', 'SSLv3']
        self.fallback_scsv = bytes([0x56, 0x00])

    def test(self, version):
        stronger_version = version + 1
        # A stronger version not supported by the server, can't test
        if version_conversion(stronger_version, False) not in self.supported_protocols:
            return False
        client_hello = ClientHello(version, self.fallback_scsv)
        client_hello = client_hello.construct_client_hello()
        response, sock = send_data_return_sock(self.address, client_hello, self.timeout, self.test_name)
        sock.close()
        # If server doesn't respond with an alert, it doesn't support SCSV fallback
        if is_server_hello(response):
            return True
        elif not response:
            return True
        # 0x15 for Content Type: Alert, 0x56 for Inappropriate Fallback
        elif response[0] == 0x15 and response[-1] == 0x56:
            return False
        else:
            return True
