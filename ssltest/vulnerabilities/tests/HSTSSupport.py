"""Vulnerability test for HSTS Support"""
import re

import requests

from ..VulnerabilityTest import VulnerabilityTest


class HSTSSupport(VulnerabilityTest):
    name = "No HSTS Support"
    short_name = "HSTS"
    description = "Test for HTTP Strict Transport Security support"

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
        self.hsts_header_key = "Strict-Transport-Security"

    def test(self, version):
        response = requests.head(
            f"https://{self.address.url}:{self.address.port}", verify=False
        )
        if self.hsts_header_key not in response.headers.keys():
            return True, "HSTS value is missing the response header"
        hsts_header_value = response.headers[self.hsts_header_key]
        hundred_and_twenty_days_in_seconds = 24 * 60 * 60 * 120
        if (
            int(re.findall("max-age=([0-9]+)", hsts_header_value)[0])
            <= hundred_and_twenty_days_in_seconds
        ):
            return True, "Max age of HSTS is too low"
        if len(re.findall("includeSub[dD]omains", hsts_header_value)) != 1:
            return True, "Sub domains are not included in HSTS"
        return False
