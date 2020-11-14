from src.logic.CryptoParamsEnum import CryptoParamsEnum as CPEnum
from src.logic.CryptoParams import CryptoParams


def get_string_rating(rating: int):
    ratings = {
        0: 'nezistené/chyba',
        1: 'bezpečné',
        2: 'nedoporúčané',
        3: 'legacy use/slabé',
        4: 'zakázané'
    }
    return ratings[rating]


def output(params: CryptoParams):
    print('Cipher suite: ' + params.cipher_suite)
    for enum in CPEnum:
        print('\t{}: {}->{}({})'.format(
            enum.string_alias,
            params.params[enum][0],
            get_string_rating(params.params[enum][1]),
            params.params[enum][1])
        )
    print('Certificate version: {}'.format(params.cert_version))
    print('Serial Number: {}'.format(params.cert_serial_number))
    print('Validity interval: {} to {}'.format(params.cert_not_valid_before, params.cert_not_valid_after))
    print('subject: ')
    for attribute in params.cert_subject:
        print('\t' + attribute.oid._name + ' = ' + attribute.value)
    print('issuer:')
    for attribute in params.cert_issuer:
        print('\t' + attribute.oid._name + ' = ' + attribute.value)
    print('rating: {}'.format(get_string_rating(params.rating)))
