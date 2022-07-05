"""Vulnerability test for BREACH"""
import requests
import re

from ..VulnerabilityTest import VulnerabilityTest


class Breach(VulnerabilityTest):
    name = short_name = "BREACH"
    description = "Test for https encoding methods"

    def __init__(self, supported_protocols, address, protocol):
        super().__init__(supported_protocols, address, protocol)
        self.valid_protocols = [
            "TLSv1.3",
            "TLSv1.2",
            "TLSv1.1",
            "TLSv1.0",
            "SSLv3",
            "SSLv2",
        ]
        self.encoding_key_string = "Content-Encoding"

    def test(self, version):
        header = {"Accept-Encoding": "gzip,deflate"}
        response = requests.head(
            f"https://{self.address.url}:{self.address.port}",
            verify=False,
            headers=header,
        )
        if self.encoding_key_string not in response.headers.keys():
            return False
        encoding = response.headers[self.encoding_key_string]
        regex_match = re.findall("gzip|deflate", encoding)

        if len(regex_match) > 1:
            return True, "gzip and deflate encodings found"
        else:
            if "gzip" in regex_match:
                return True, "gzip encoding found"
            elif "gzip" in regex_match:
                return True, "deflate encoding found"
        return False
