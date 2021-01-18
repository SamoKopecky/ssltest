import sys

sys.path.append('../')

from src.console_output.console_output import console_output
from src.logic.session_info import get_website_info
from src.logic.CryptoParams import CryptoParams

if __name__ == '__main__':
    cert, cipher, protocol = get_website_info(str(input("Webová adresa: ") or 'vutbr.cz'))
    parameters = CryptoParams(cert, cipher, protocol)
    parameters.parse_cipher_suite()
    parameters.parse_protocol_version()
    parameters.rate_parameters()
    console_output(parameters)
