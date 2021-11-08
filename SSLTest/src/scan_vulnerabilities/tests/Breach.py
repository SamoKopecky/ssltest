"""Vulnerability test for BREACH"""
import requests

from ..VulnerabilityTest import VulnerabilityTest


class Breach(VulnerabilityTest):
    test_name = "BREACH"

    def __init__(self, supported_protocols, address, timeout, protocol):
        super().__init__(supported_protocols, address, timeout, protocol)
        self.valid_protocols = ['TLSv1.3', 'TLSv1.2', 'TLSv1.1', 'TLSv1.0', 'SSLv3', 'SSLv2']
        self.encoding_key_string = "Content-Encoding"

    def test(self, version):
        # TODO: Test
        header = {
            "Accept-Encoding": "gzip,deflate"
        }
        response = requests.head(f"https://{self.address.url}:{self.address.port}", verify=False, headers=header)
        if self.encoding_key_string not in response.headers.keys():
            return False
        encoding = response.headers[self.encoding_key_string]
        # TODO: change to regex and add comments on positives
        if "deflate" in encoding or "gzip" in encoding:
            return True
        return False
