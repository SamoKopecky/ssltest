"""Vulnerability test for Fallback SCSV Support"""

from ..VulnerabilityTest import VulnerabilityTest, protocol_version_conversion
from ...core.ClientHello import ClientHello
from ...main.utils import send_data_return_sock, is_server_hello


class FallbackSCSVSupport(VulnerabilityTest):
    name = 'No Fallback SCSV Support'
    short_name = 'Fallback SCSV'
    description = 'Test if fallback Signaling Cipher Suite Value is available'

    def __init__(self, supported_protocols, address, timeout, protocol):
        super().__init__(supported_protocols, address, timeout, protocol)
        self.valid_protocols = ['TLSv1.2', 'TLSv1.1', 'TLSv1.0', 'SSLv3']
        self.fallback_scsv = bytes([0x56, 0x00])

    def test(self, version):
        """
        Check if the server supports Fallback SCSV

        :param int version: SSL/TLS version
        :return: Whether the server don't support fallback SCSV
        :rtype: bool
        """
        usable_protocols = list(
            filter(lambda p: p in self.valid_protocols, self.supported_protocols))
        if len(usable_protocols) == 1:
            return False
        usable_protocols = sorted(usable_protocols)
        second_worst_protocol = protocol_version_conversion(
            usable_protocols[-2])
        client_hello = ClientHello(second_worst_protocol, self.fallback_scsv)
        client_hello = client_hello.construct_client_hello()
        response, sock = send_data_return_sock(
            self.address, client_hello, self.timeout, self.name)
        sock.close()
        # If server doesn't respond with an alert, it doesn't support SCSV fallback
        if is_server_hello(response):
            return True, "Server didn't respond with an alert"
        elif not response:
            return True
        # 0x15 for Content Type: Alert, 0x56 for Inappropriate Fallback
        elif response[0] == 0x15 and response[-1] == 0x56:
            return False
        else:
            return True
