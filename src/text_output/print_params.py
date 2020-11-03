from src.parser.CryptoParams import CryptoParams


def print_params(crypto_params: CryptoParams):
    print("Cipher suite : " + crypto_params.cipher_suite)
    print("TLS/SSL version : " + crypto_params.params[crypto_params.PROTOCOL] + 'v' + crypto_params.params[
        crypto_params.PROTOCOL_VERSION])
    print("Certificate version: " + crypto_params.cert_version)
    print("Serial Number: " + crypto_params.cert_serial_number)
    print("Signature Algorithm: " + crypto_params.params[crypto_params.CERT_SIG_ALG])
    print("Asymmetric cryptography key length : " + str(
        crypto_params.params[crypto_params.CERT_SIG_ALG_KEY_LEN]) + " bits")
    print("Validity interval: " + crypto_params.cert_not_valid_before + " to " + crypto_params.cert_not_valid_after)
    print('subject: ')
    for attribute in crypto_params.cert_subject:
        print(attribute.oid._name + ' = ' + attribute.value)
    print('issuer:')
    for attribute in crypto_params.cert_issuer:
        print(attribute.oid._name + ' = ' + attribute.value)
