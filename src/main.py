from src.text_output.print_params import print_params
from src.parser.session_info import get_website_info
from src.parser.CryptoParams import CryptoParams

if __name__ == '__main__':
    cert, cipher, protocol = get_website_info(str(input("Domain name : ") or 'stackoverflow.com'))
    pars = CryptoParams(cert, cipher, protocol)
    print_params(pars)
    print(pars.params)
