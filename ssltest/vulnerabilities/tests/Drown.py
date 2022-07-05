"""Vulnerability test for DROWN"""

from ..CipherSuiteTest import CipherSuiteTest
from ...network.SSLv2 import SSLv2


class Drown(CipherSuiteTest):
    name = short_name = "DROWN"
    description = "Test for rsa key exchange suites with ssl2 support"

    def __init__(self, supported_protocols, address, protocol):
        super().__init__(supported_protocols, address, protocol)
        self.valid_protocols = ["SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2"]
        self.scan_once = False
        self.sslv2_vulnerable = True
        self.filter_regex = "TLS_RSA"

    def test(self, version):
        """
        Scan for DROWN vulnerability (CVE-2016-0800)

        :param int version: SSL/TLS version
        :return: Whether the server is vulnerable
        :rtype: bool
        """
        if (
            "SSLv2" not in self.supported_protocols
            or self.supported_protocols == ["SSLv2"]
            or not self.sslv2_vulnerable
        ):
            return False

        # All cipher suites that use RSA for kex
        return super().test(version)

    def run_once(self):
        """
        Scan for the EXPORT cipher suites in SSLv2 support
        """
        if "SSLv2" not in self.supported_protocols:
            return
        sslv2 = SSLv2(self.address)
        sslv2.data = sslv2.connect()
        sslv2.parse_cipher_suite()
        export_cipher_suites = list(
            filter(lambda cs: "EXPORT" in cs, sslv2.server_cipher_suites)
        )
        if len(export_cipher_suites) == 0:
            self.sslv2_vulnerable = False
