import sys

sys.path.append('../')

from src.console_output.console_output import console_output
from src.parameter_rating.session_info import get_website_info
from src.parameter_rating.CryptoParams import CryptoParams
from src.scan.scan_webserver_version import scan_versions


def main():
    website = str(input("Webová adresa: ") or 'vutbr.cz')
    cert, cipher, protocol, supported_versions = get_website_info(website)
    parameters = CryptoParams(cert, cipher, protocol, supported_versions)
    parameters.parse_cipher_suite()
    parameters.parse_protocol_version()
    parameters.rate_parameters()
    parameters.rate_supported_protocol_versions()
    parameters.final_rating()
    console_output(parameters, scan_versions(website))


if __name__ == '__main__':
    main()
