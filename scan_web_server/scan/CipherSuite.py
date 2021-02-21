from .PType import PType
from ..utils import *


class CipherSuite:

    def __init__(self, cipher_suite, protocol):
        # Create a dictionary for cipher suite parameters with PType keys
        self.parameters = {enum: ['N/A', 0] for enum in PType if enum.is_cipher_suite}
        self.parameters[PType.protocol] = ['N/A', 0]
        self.cipher_suite = cipher_suite
        self.parameters[PType.protocol][0] = protocol
        self.rating = 0

    def parse_cipher_suite(self):
        """
        Parses used cipher suite into python readable objects.

        The cipher suite is split into each parameter and then sorted
        to categories with the help of a json file. Categories are
        defined in PType.py class.
        """
        json_data = read_json('cipher_parameters.json')
        raw_parameters = self.cipher_suite.split('_')
        raw_parameters.remove('TLS')
        parameter_enums = list(self.parameters.keys())
        parameter_enums.remove(PType.protocol)
        # For each parameter iterate through each enum value until a match is found
        for raw_parameter in raw_parameters:
            for enum in parameter_enums:
                if raw_parameter in json_data[enum.name].split(','):
                    parameter_enums.remove(enum)
                    self.parameters[enum] = [raw_parameter, 0]
                    break

    def rate_cipher_suite(self):
        """
        Rates all cipher suite parameters.

        First part is used if a length parameter needs to be rated
        Second part is used for not length parameters
        """
        for enum in list(self.parameters.keys()):
            # 1st part
            if enum == PType.sym_enc_algorithm_key_length or \
                    enum == PType.sym_ecn_algorithm_block_mode_number:
                self.parameters[enum][1] = rate_key_length_parameter(
                    self.parameters[enum.key_pair][0],
                    self.parameters[enum][0], enum
                )
                continue
            # 2nd part
            self.parameters[enum][1] = rate_parameter(enum, self.parameters[enum][0])
        self.rating = max([rating[1] for rating in self.parameters.values()])

    def parse_protocol_version(self):
        """
        Reads the protocol version and applies special edge cases.

        Might add more.
        """
        if self.parameters[PType.protocol][0] == 'TLSv1.3':
            self.parameters[PType.kex_algorithm][0] = 'ECDHE'

    def rate(self):
        self.parse_cipher_suite()
        self.parse_protocol_version()
        self.rate_cipher_suite()
