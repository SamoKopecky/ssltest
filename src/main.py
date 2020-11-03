from src.main_info import get_website_info
from src.CryptographyParameters import CryptographyParameters

if __name__ == '__main__':
    cipher = get_website_info(str(input("Domain name : ") or 'stackoverflow.com'))
    pars = CryptographyParameters()
    pars.parse_cipher_suite(cipher)

