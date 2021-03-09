import json
import re
import os
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric import ed448
from .exceptions.NoIanaPairFound import NoIanaPairFound
from .rate.PType import PType


def convert_openssh_to_iana(search_term: str):
    """
    Convert openssh format of a cipher suite to IANA format.

    Raises IndexError if not conversion is found
    :param search_term: cipher suite
    :return: converted cipher suite
    """
    json_data = read_json('iana_openssl_cipher_mapping.json')
    for row in json_data:
        if json_data[row] == search_term:
            return row
    raise NoIanaPairFound()


def read_json(file_name: str):
    """
    Read a json file and return its content.

    :param file_name: json file name
    :return: json data in python objects
    """
    root_dir = os.path.dirname(os.path.abspath(__file__))
    file = open(f'{root_dir}/../resources/{file_name}', 'r')
    json_data = json.loads(file.read())
    file.close()
    return json_data


def rate_key_length_parameter(algorithm_type: PType, key_len: str, key_len_type: PType):
    """
    Get the rating of an algorithm key length.

    :param key_len_type: type of the key length parameter
    :param algorithm_type: algorithm of the key length
    :param key_len: key length of the algorithm
    :return: rating of a parameter pair or 0 if a rating isn't defined or found
    """
    functions = {
        ">=": lambda a, b: a >= b,
        ">>": lambda a, b: a > b,
        "<=": lambda a, b: a <= b,
        "<<": lambda a, b: a < b,
        "==": lambda a, b: a == b
    }
    levels_str = read_json('security_levels.json')[key_len_type.name]
    if key_len == 'N/A':
        return 0
    for idx in range(1, 5):
        levels = levels_str[str(idx)].split(',')
        if algorithm_type in levels:
            # gets the operation assigned to the algorithm key length
            operation = levels[levels.index(algorithm_type) + 1]
            function = functions[operation[:2]]
            if function(int(key_len), int(operation[2:])):
                return idx
    return 0


def rate_parameter(p_type: PType, parameter: str):
    """
    Rate a parameter using a defined json file.

    :param parameter: parameter that is going to be rated
    :param p_type: specifies which parameter category should be used for rating
    :return: if a rating is found for a parameter returns that rating,
    if not 0 is returned (default value)
    """
    security_levels_json = read_json('security_levels.json')
    if parameter == 'N/A':
        return 0
    for idx in range(1, 5):
        if parameter in security_levels_json[p_type.name][str(idx)].split(','):
            return idx
    return 0


def get_first_key(dictionary: dict):
    return list(dictionary.keys())[0]


def pub_key_alg_from_cert(public_key):
    """
    Get the public key algorithm from a certificate.

    :param public_key: instance of a public key
    :return: string representation of a parameter
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


def get_sig_alg_from_oid(oid: x509.ObjectIdentifier):
    """
    Get a signature algorithm from an oid of a certificate

    :param oid: object identifier
    :return: signature algorithm in string representation
    """
    values = list(x509.SignatureAlgorithmOID.__dict__.values())
    keys = list(x509.SignatureAlgorithmOID.__dict__.keys())
    return keys[values.index(oid)].split('_')[0]


def fix_url(url: str):
    """
    Extract the root domain name.

    :param url: hostname address to be checked
    :return: fixed hostname address
    """
    print('Correcting url...')
    if url[:4] == 'http':
        # Removes http(s):// and anything after TLD (*.com)
        url = re.search('[/]{2}([^/]+)', url).group(1)
    else:
        # Removes anything after TLD (*.com)
        url = re.search('^([^/]+)', url).group(0)
    print('Corrected url: {}'.format(url))
    return url


def dump_to_dict(cipher_suite, certificate_parameters, protocol_support,
                 certificate_non_parameters, versions, port, url):
    """
    Dump web server parameters to a single dict.

    :param cipher_suite: tuple containing parameters and the worst rating
    :param certificate_parameters: tuple containing parameters and the worst rating
    :param certificate_non_parameters: certificate parameters such as subject/issuer
    :param protocol_support: dictionary of supported tls protocols
    :param versions: web server versions
    :param port: scanned port
    :param url: scanned url
    :return: dictionary
    """
    dump = {}

    # Parameters
    worst_rating = max([cipher_suite[1], certificate_parameters[1]])
    parameters = {key.name: value for key, value in cipher_suite[0].items()}
    parameters.update({key.name: value for key, value in certificate_parameters[0].items()})
    parameters.update({'rating': worst_rating})

    # Other cert info
    certificate_info = {key.name: value for key, value in certificate_non_parameters.items()}

    # Protocol support
    protocols = protocol_support[0]
    protocols.update({'rating': protocol_support[1]})

    dump.update({'parameters': parameters})
    dump.update({'certificate_info': certificate_info})
    dump.update({'protocol_support': protocols})
    dump.update({'web_server_versions': versions})
    return {f'{url}:{port}': dump}
