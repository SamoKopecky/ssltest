from src.parser.CryptoParamsEnum import CryptoParamsEnum as CPEnum
from src.parser.CryptoParams import CryptoParams


def output(params: CryptoParams):
    print('Cipher suite: ' + params.cipher_suite)
    for enum in CPEnum:
        print('\t{}: {}:{}'.format(enum.name, params.params[enum][0], params.params[enum][1]))
    print('Certificate version: {}'.format(params.cert_version))
    print('Serial Number: {}'.format(params.cert_serial_number))
    print('Validity interval: {} to {}'.format(params.cert_not_valid_before, params.cert_not_valid_after))
    print('subject: ')
    for attribute in params.cert_subject:
        print('\t' + attribute.oid._name + ' = ' + attribute.value)
    print('issuer:')
    for attribute in params.cert_issuer:
        print('\t' + attribute.oid._name + ' = ' + attribute.value)
    print('rating: {}'.format(str(params.rating)))
