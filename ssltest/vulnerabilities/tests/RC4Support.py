"""Vulnerability test for RC4 Support"""

from ..CipherSuiteTest import CipherSuiteTest


class RC4Support(CipherSuiteTest):
    name = short_name = "RC4 Support"
    description = "Test for RC4 cipher suites"

    def __init__(self, supported_protocols, address, protocol):
        super().__init__(supported_protocols, address, protocol)
        self.valid_protocols = ["TLSv1.2", "TLSv1.1", "TLSv1.0", "SSLv3"]
        if (
            "TLSv1.0" in self.supported_protocols
            and "TLSv1.1" in self.supported_protocols
        ):
            self.valid_protocols.remove("TLSv1.1")
        self.scan_once = False
        self.filter_regex = "RC4"
