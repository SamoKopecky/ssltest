from scan_web_server.utils import *
from .Parameters import Parameters
from .PType import PType


class CipherSuite(Parameters):

    def __init__(self, cipher_suite, protocol):
        # Create a dictionary for cipher suite parameters with PType keys
        super().__init__()
        self.parameters = {enum: {} for enum in PType if enum.is_cipher_suite}
        self.protocol = protocol
        self.cipher_suite = cipher_suite

    def parse_cipher_suite(self):
        """
        Parse used cipher suite into python readable objects.

        The cipher suite is split into each parameter and then sorted
        to categories with the help of a json file. Categories are
        defined in PType.py class.
        """
        json_data = read_json('cipher_parameters.json')
        raw_parameters = self.cipher_suite.split('_')
        raw_parameters.remove('TLS')
        parameter_enums = list(self.parameters.keys())
        # For each parameter iterate through each enum value until a match is found
        for raw_parameter in raw_parameters:
            for enum in parameter_enums:
                if raw_parameter in json_data[enum.name].split(','):
                    parameter_enums.remove(enum)
                    self.parameters[enum] = {raw_parameter: 0}
                    break
        for enum in list(self.parameters.keys()):
            if not bool(self.parameters[enum]):
                self.parameters[enum] = {'N/A': 0}

    def rate_cipher_suite(self):
        """
        Rate all cipher suite parameters.
        """
        rateable_parameters = list(self.parameters.keys())
        key_types = [PType.sym_enc_algorithm_key_length, PType.sym_ecn_algorithm_block_mode_number]
        self.rate_parameters(rateable_parameters, key_types)

    def parse_protocol_version(self):
        """
        Read the protocol version and apply special edge cases.

        Might add more.
        """
        self.parameters[PType.protocol] = {self.protocol: 0}
        if self.protocol == 'TLSv1.3':
            self.parameters[PType.kex_algorithm] = {'ECDHE': 0}

    def rate(self):
        self.parse_cipher_suite()
        self.parse_protocol_version()
        self.rate_cipher_suite()
        return self.rating
