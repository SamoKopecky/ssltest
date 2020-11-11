from src.console_output.console_output import output
from src.logic.session_info import get_website_info
from src.logic.CryptoParams import CryptoParams

if __name__ == '__main__':
    cert, cipher, protocol = get_website_info(str(input("Domain name: ") or 'stackoverflow.com'))
    pars = CryptoParams(cert, cipher, protocol)
    pars.parse_cipher_suite()
    pars.parse_protocol_version()
    pars.rate_parameters()
    output(pars)
