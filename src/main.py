import sys
import ssl

sys.path.append('../')

from src.console_output.console_output import console_output
from src.logic.session_info import get_website_info
from src.logic.CryptoParams import CryptoParams

if __name__ == '__main__':
    cert, cipher, protocol, supported_versions = get_website_info(str(input("Webová adresa: ") or 'vutbr.cz'))
    parameters = CryptoParams(cert, cipher, protocol, supported_versions)
    parameters.parse_cipher_suite()
    parameters.parse_protocol_version()
    parameters.rate_parameters()
    parameters.rate_supported_protocol_versions()
    console_output(parameters)
