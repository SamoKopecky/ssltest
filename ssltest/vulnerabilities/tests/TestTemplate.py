"""<Delete this to to be able to run this test>Vulnerability test for <test_name>"""

from ..VulnerabilityTest import VulnerabilityTest


class TestTemplate(VulnerabilityTest):
    name = "Test name in results"
    short_name = "Short test name in -h output"
    description = "Test description in -h output"

    def __init__(self, supported_protocols, address, protocol):
        super().__init__(supported_protocols, address, protocol)
        self.valid_protocols = ["TLSv1.2"]  # Add protocols to scan on
        self.scan_once = False  # Run tess for all available protocols
        self.custom_variable = ""

    def test(self, version):
        # return (False, "Optional test result description")
        return False

    def test_once(self):
        self.custom_variable = "This was done before tests were ran"
