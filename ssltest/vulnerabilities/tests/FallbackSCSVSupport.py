"""Vulnerability test for Fallback SCSV Support"""

from ..VulnerabilityTest import VulnerabilityTest, protocol_version_conversion
from ...network.ClientHello import ClientHello
from ...sockets.SafeSocket import SafeSocket


class FallbackSCSVSupport(VulnerabilityTest):
    name = "No Fallback SCSV Support"
    short_name = "Fallback SCSV"
    description = "Test if fallback Signaling Cipher Suite Value is available"

    def __init__(self, supported_protocols, address, protocol):
        super().__init__(supported_protocols, address, protocol)
        self.valid_protocols = ["TLSv1.2", "TLSv1.1", "TLSv1.0", "SSLv3"]
        self.fallback_scsv = bytes([0x56, 0x00])

    def test(self, version):
        """
        Check if the server supports Fallback SCSV

        :param int version: SSL/TLS version
        :return: Whether the server don't support fallback SCSV
        :rtype: bool
        """
        usable_protocols = list(
            filter(lambda p: p in self.valid_protocols, self.supported_protocols)
        )
        if len(usable_protocols) == 1:
            return False
        usable_protocols = sorted(usable_protocols)
        second_worst_protocol = protocol_version_conversion(usable_protocols[-2])

        client_hello = ClientHello(
            second_worst_protocol, self.fallback_scsv
        ).pack_client_hello()
        with SafeSocket(self.address, self.usage) as sock:
            sock.send(client_hello)
            response = sock.receive()

        # If server doesn't respond with an alert, it doesn't support SCSV fallback
        if ClientHello.is_server_hello(response):
            return True, "Server didn't respond with an alert"
        elif not response:
            return True
        # 0x15 for Content Type: Alert, 0x56 for Inappropriate Fallback
        elif response[0] == 0x15 and response[-1] == 0x56:
            return False
        else:
            return True
