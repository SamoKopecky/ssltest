"""Vulnerability test for SWEET 32"""

from ..CipherSuiteTest import CipherSuiteTest


class Sweet32(CipherSuiteTest):
    name = short_name = "SWEET32"
    description = "Test support for 64-bit key length encryption"

    def __init__(self, supported_protocols, address, protocol):
        super().__init__(supported_protocols, address, protocol)
        self.valid_protocols = ["TLSv1.2", "TLSv1.1", "TLSv1.0", "SSLv3"]
        self.scan_once = False
        self.filter_regex = "DES"
