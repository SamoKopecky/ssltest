"""Vulnerability test for LOGJAM vulnerability"""

from ..CipherSuiteTest import CipherSuiteTest


class Logjam(CipherSuiteTest):
    name = short_name = "LOGJAM"
    description = "Test for DH + EXPORT cipher suites"

    def __init__(self, supported_protocols, address, protocol):
        super().__init__(supported_protocols, address, protocol)
        self.valid_protocols = ["TLSv1.2", "TLSv1.1", "TLSv1.0", "SSLv3"]
        self.scan_once = False
        self.filter_regex = "DH.*EXPORT"
