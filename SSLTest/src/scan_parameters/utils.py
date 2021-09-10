import logging
import re

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519, ed448

from .ratable.PType import PType
from ..utils import read_json


def rate_key_length_parameter(algorithm_type, key_len, key_len_type):
    """
    Get the rating of an algorithm key length

    Parameter is rated using the security_levels.json file if no rating is
    found 0 is returned

    :param PType algorithm_type: Algorithm of the key length
    :param str key_len: Key length of the algorithm
    :param PType key_len_type: Type of the key length parameter
    :return: Rating of the parameter
    :rtype: str
    """
    functions = {
        ">=": lambda a, b: a >= b,
        ">>": lambda a, b: a > b,
        "<=": lambda a, b: a <= b,
        "<<": lambda a, b: a < b,
        "==": lambda a, b: a == b
    }
    # TODO: All of the algorithms are not yet added to the security_levels.json
    levels_str = read_json('security_levels.json')[key_len_type.name]
    if key_len == 'N/A':
        return '0'
    for idx in range(1, 5):
        levels = levels_str[str(idx)].split(',')
        if algorithm_type in levels:
            # gets the operation assigned to the algorithm key length
            operation = levels[levels.index(algorithm_type) + 1]
            function = functions[operation[:2]]
            if function(int(key_len), int(operation[2:])):
                return str(idx)
    return '0'


def rate_parameter(p_type, parameter):
    """
    Rate a parameter using a defined json file

    :param PType p_type: Specifies which parameter category should be used for rating
    :param str parameter: Parameter that is going to be rated
    :return: Rating of the parameter else 0
    :rtype: str
    """
    # TODO: All of the algorithms are not yet added to the security_levels.json
    security_levels_json = read_json('security_levels.json')
    if parameter == 'N/A':
        return '0'
    for idx in range(1, 5):
        if parameter in security_levels_json[p_type.name][str(idx)].split(','):
            return str(idx)
    return '0'


def pub_key_alg_from_cert(public_key):
    """
    Get the public key algorithm from a certificate

    :param public_key: Instance of a public key
    :return: Parameter
    :rtype: str
    """
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return 'EC'
    elif isinstance(public_key, rsa.RSAPublicKey):
        return 'RSA'
    elif isinstance(public_key, dsa.DSAPublicKey):
        return 'DSA'
    elif isinstance(public_key, ed25519.Ed25519PublicKey) or isinstance(public_key, ed448.Ed448PublicKey):
        return 'ECDSA'
    else:
        return 'N/A'


def get_sig_alg_from_oid(oid):
    """
    Get a signature algorithm from an oid of a certificate

    :param x509.ObjectIdentifier oid: Object identifier
    :return: Signature algorithm
    :rtype: str
    """
    values = list(x509.SignatureAlgorithmOID.__dict__.values())
    keys = list(x509.SignatureAlgorithmOID.__dict__.keys())
    return keys[values.index(oid)].split('_')[0]


def fix_url(url):
    """
    Extract the root domain name

    :param str url: Url of the web server
    :return: Fixed hostname address
    :rtype: str
    """
    logging.info('Correcting url...')
    if url[:4] == 'http':
        # Removes http(s):// and anything after TLD (*.com)
        url = re.search('[/]{2}([^/]+)', url).group(1)
    else:
        # Removes anything after TLD (*.com)
        url = re.search('^([^/]+)', url).group(0)
    logging.info('Corrected url: {}'.format(url))
    return url
