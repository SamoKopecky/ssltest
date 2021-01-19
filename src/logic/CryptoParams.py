import sys

sys.path.append('../../')

from src.logic.CryptoParamsEnum import CryptoParamsEnum as CPEnum
from src.utils import read_json, compare_key_length, pub_key_alg_from_cert, get_sig_alg_from_oid


class CryptoParams:
    """
    Holds all the information about the security
    of a webserver and functions for rating them.
    """
    def __init__(self, cert, cipher_suite, protocol, supported_versions):
        """
        Constructor for CryptoParams class.

        Gathers data from created connections in the session_info.py file
        """
        # Create default dictionary for cipher suite and certificate parameters
        self.params = {enum: ['N/A', 0] for enum in CPEnum}
        # Create default dictionary for supported SSL/TLS versions
        self.supported_versions = {version: 0 for version in supported_versions}
        self.cert = cert
        self.cert_version = str(self.cert.version.value)
        self.cert_serial_number = str(self.cert.serial_number)
        self.cert_not_valid_before = str(self.cert.not_valid_before.date())
        self.cert_not_valid_after = str(self.cert.not_valid_after.date())
        self.cert_subject = self.cert.subject
        self.cert_issuer = self.cert.issuer
        self.cipher_suite = cipher_suite
        self.params[CPEnum.CERT_SIG_ALG][0] = get_sig_alg_from_oid(self.cert.signature_algorithm_oid)
        self.params[CPEnum.CERT_SIG_ALG_HASH_FUN][0] = str(self.cert.signature_hash_algorithm.name).upper()
        self.params[CPEnum.CERT_PUB_KEY_LEN][0] = str(self.cert.public_key().key_size)
        self.params[CPEnum.PROTOCOL][0] = protocol
        # Top level rating of a website
        self.rating = 0

    def parse_cipher_suite(self):
        """
        Parses used cipher suite into python readable objects.

        The cipher suite is split into each parameter and then sorted
        to categories with the help of a json file. Categories are
        defined in CryptoParamsEnum.py class.
        """
        jdata = read_json('cipher_parameters.json')
        raw_params = self.cipher_suite.split('_')
        raw_params.remove('TLS')
        # List of all cipher suite enum categories
        cipher_suite_enums = [enum for enum in CPEnum if enum.is_parsable]
        for param in raw_params:
            for enum in cipher_suite_enums:
                if param in jdata[enum.name].split(','):
                    cipher_suite_enums.remove(enum)
                    self.params[enum] = [param, 0]
                    break
        # Needed when the public key algorithm is not defined in cipher suite
        if self.params[CPEnum.CERT_PUB_KEY_ALG][0] == 'N/A':
            self.params[CPEnum.CERT_PUB_KEY_ALG][0] = pub_key_alg_from_cert(self.cert.public_key())

    def rate_parameters(self):
        """
        Rates all cipher suite and certificates parameters.

        First part is used if a length parameter needs to be rated
        Second part is used for not length parameters
        After all parameters have been rated the worse rating is recorded
        """
        jdata = read_json('security_levels.json')
        for enum in CPEnum:
            # 1st part
            if enum == CPEnum.SYM_ENCRYPT_ALG_KEY_LEN or \
                    enum == CPEnum.CERT_PUB_KEY_LEN or \
                    enum == CPEnum.SYM_ENCRYPT_ALG_BLOCK_MODE_NUMBER:
                self.params[enum][1] = compare_key_length(
                    self.params[enum.key_pair][0],
                    self.params[enum][0],
                    jdata[enum.name]
                )
                continue
            # 2nd part
            self.params[enum][1] = self.rate_parameter(enum, self.params[enum][0])
        self.rating = max([solo_rating[1] for solo_rating in self.params.values()])

    @staticmethod
    def rate_parameter(enum, param):
        """
        Helper function for rating a parameter from a json file.

        :param enum: specifies which parameter category should be used for rating
        :param jdata: read data form a json file
        :param param: parameter that is going to be rated
        :return: if a rating is found for a parameter returns that rating,
        if not 0 is returned (default value)
        """
        jdata = read_json('security_levels.json')
        for idx in range(1, 5):
            if param in jdata[enum.name][str(idx)].split(','):
                return idx
        return 0

    def parse_protocol_version(self):
        """
        Reads the protocol version and applies special edge cases.
        """
        if self.params[CPEnum.PROTOCOL][0] == 'TLSv1.3':
            self.params[CPEnum.KEY_EXCHANGE_ALG][0] = 'ECDHE'

    def rate_supported_protocol_versions(self):
        """
        Rates the protocol version and name of every protocol
        with which can a connection be made to the website.
        """
        for key in self.supported_versions:
            self.supported_versions[key] = self.rate_parameter(CPEnum.PROTOCOL, key)
