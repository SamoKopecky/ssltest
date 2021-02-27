import json
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric import ed448
from .exceptions.NoIanaPairFound import NoIanaPairFound


def convert_openssh_to_iana(search_term):
    """
    Converts openssh format of a cipher suite to IANA format.

    Raises IndexError if not conversion is found
    :param search_term: cipher suite
    :return: converted cipher suite
    """
    json_data = read_json('iana_openssl_cipher_mapping.json')
    for row in json_data:
        if json_data[row] == search_term:
            return row
    raise NoIanaPairFound()


def read_json(file_name):
    """
    Helper function for reading a json file.

    :param file_name: json file name
    :return: json data in python objects
    """
    file = open('resources/' + file_name, 'r')
    json_data = json.loads(file.read())
    file.close()
    return json_data


def rate_key_length_parameter(algorithm, key_len, enum):
    """
    Derives the rating of a algorithm key length.

    :param enum:
    :param algorithm: algorithm
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
    levels_str = read_json('security_levels.json')[enum.name]
    if key_len == 'N/A':
        return 0
    for idx in range(1, 5):
        levels = levels_str[str(idx)].split(',')
        if algorithm in levels:
            # gets the operation assigned to the algorithm key length
            operation = levels[levels.index(algorithm) + 1]
            function = functions[operation[:2]]
            if function(int(key_len), int(operation[2:])):
                return idx
    return 0


def rate_parameter(enum, parameter):
    """
    Helper function for rating a parameter from a json file.

    :param enum: specifies which parameter category should be used for rating
    :param parameter: parameter that is going to be rated
    :return: if a rating is found for a parameter returns that rating,
    if not 0 is returned (default value)
    """
    security_levels_json = read_json('security_levels.json')
    if parameter == 'N/A':
        return 0
    for idx in range(1, 5):
        if parameter in security_levels_json[enum.name][str(idx)].split(','):
            return idx
    return 0


def pub_key_alg_from_cert(public_key):
    """
    Gets the public key algorithm from the certificate.

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


def get_sig_alg_from_oid(oid):
    """
    Gets the signature algorithm from an oid of a certificate

    :param oid: object identifier
    :return: signature algorithm in string representation
    """
    values = list(x509.SignatureAlgorithmOID.__dict__.values())
    keys = list(x509.SignatureAlgorithmOID.__dict__.keys())
    return keys[values.index(oid)].split('_')[0]
