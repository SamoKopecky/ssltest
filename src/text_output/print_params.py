from src.parser.CryptoParamsEnum import CryptoParamsEnum as CPEnum
from src.parser.CryptoParams import CryptoParams


def print_params(crypto_params: CryptoParams):
    print("Cipher suite : " + crypto_params.cipher_suite)
    print("TLS/SSL version : " + crypto_params.params[CPEnum.PROTOCOL][0] + 'v' + crypto_params.params[
        CPEnum.PROTOCOL_VERSION][0])
    print("Certificate version: " + crypto_params.cert_version)
    print("Serial Number: " + crypto_params.cert_serial_number)
    print("Signature Algorithm: " + crypto_params.params[CPEnum.CERT_SIG_ALG][0])
    print("Asymmetric cryptography key length : " + str(
        crypto_params.params[CPEnum.CERT_SIG_ALG_KEY_LEN][0]) + " bits")
    print("Validity interval: " + crypto_params.cert_not_valid_before + " to " + crypto_params.cert_not_valid_after)
    print('subject: ')
    for attribute in crypto_params.cert_subject:
        print(attribute.oid._name + ' = ' + attribute.value)
    print('issuer:')
    for attribute in crypto_params.cert_issuer:
        print(attribute.oid._name + ' = ' + attribute.value)
    print('rating: ' + str(crypto_params.rating))
