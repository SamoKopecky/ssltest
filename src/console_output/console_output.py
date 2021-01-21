import sys

sys.path.append('../../')

from src.parameter_rating.CryptoParamsEnum import CryptoParamsEnum as CPEnum
from src.parameter_rating.CryptoParams import CryptoParams


def get_string_rating(rating: int):
    """
    Converts numeric value into a string

    :param rating: rating to be converted
    :return: converted rating
    """
    ratings = {
        0: 'nezistené/chyba',
        1: 'bezpečné',
        2: 'nedoporúčané',
        3: 'zastarané',
        4: 'zakázané'
    }
    return ratings[rating]


def console_output(params: CryptoParams):
    """
    Prints the rated parameters in a console.

    :param params: parameters to be printed out
    """
    print('Podporované verzie protokolov:')
    for key in params.supported_versions:
        print('\t{}->{}({})'.format(
            key,
            get_string_rating(params.supported_versions[key]),
            params.supported_versions[key])
        )
    print('Kryptografická sada: \n\t{}'.format(params.cipher_suite))
    print('Kryptografické parametre:')
    for enum in CPEnum:
        if params.params[enum][1] == 0:
            continue
        print('\t{}: {}->{}({})'.format(
            enum.string_alias,
            params.params[enum][0],
            get_string_rating(params.params[enum][1]),
            params.params[enum][1])
        )
    print('\tCelková bezpečnosť kryptografickej sady: {}({})'.format(get_string_rating(params.rating), params.rating))
    print('Ostatné informácie o certifikáte:')
    print('\tVerzia certifikátu: {}'.format(params.cert_version))
    print('\tSériové číslo: {}'.format(params.cert_serial_number))
    print('\tInterval platnosti: {} do {}'.format(params.cert_not_valid_before, params.cert_not_valid_after))
    print('\tpredmet:')
    for attribute in params.cert_subject:
        print('\t\t' + attribute.oid._name + ' = ' + attribute.value)
    print('\tvydavateľ:')
    for attribute in params.cert_issuer:
        print('\t\t' + attribute.oid._name + ' = ' + attribute.value)
