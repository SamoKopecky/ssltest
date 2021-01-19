import json
import os
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric import ed448


def convert_openssh_to_iana(search_term):
    """
    Converts openssh format of a cipher suite to IANA format.

    Raises IndexError if not conversion is found
    :param search_term: cipher suite
    :return: converted cipher suite
    """
    jdata = read_json('iana_openssl_cipher_mapping.json')
    for row in jdata:
        if jdata[row] == search_term:
            return row
    raise IndexError("cipher is not contained in .json file")


def read_json(file_name):
    """
    Helper function for reading a json file.

    :param file_name: json file name
    :return: json data in python objects
    """
    root_dir = os.path.dirname(os.path.abspath(__file__))
    file = open(root_dir + '/../resources/' + file_name, 'r')
    jdata = json.loads(file.read())
    file.close()
    return jdata


def compare_key_length(algorithm, key_len, levels_str):
    """
    Derives the rating of a algorithm key length.

    :param algorithm: algorithm
    :param key_len: key length of the algorithm
    :param levels_str: security levels read from a json file of the specific category
    :return: rating of a parameter pair or 0 if a rating isn't defined or found
    """
    if key_len == 'N/A':
        return 0
    for idx in range(1, 5):
        levels = levels_str[str(idx)].split(',')
        if algorithm in levels:
            # gets the operation assigned to the algorithm key length
            operation = levels[levels.index(algorithm) + 1]
            if return_function_from_operation(operation[:2])(int(key_len), int(operation[2:])):
                return idx
    return 0


def return_function_from_operation(operation):
    """
    Defines operations used for comparing key lengths

    :param operation: string representation of an operation
    :return: lambda function of an operation
    """
    functions = {
        ">=": lambda a, b: a >= b,
        ">>": lambda a, b: a > b,
        "<=": lambda a, b: a <= b,
        "<<": lambda a, b: a < b,
        "==": lambda a, b: a == b
    }
    return functions[operation]


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
