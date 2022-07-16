import logging

from .PType import PType
from .Parameters import Parameters
from ...core.utils import read_json

json_data = read_json("cipher_parameters.json")
log = logging.getLogger(__name__)


class CipherSuite(Parameters):
    def __init__(self, cipher_suite, protocol=None):
        """
        Constructor

        :param str cipher_suite: Webserver cipher suite
        :param str protocol: SSL/TLS Protocol string
        """
        super().__init__()
        # Create a dictionary for cipher suite parameters with PType keys
        self.parameters = {enum: {} for enum in PType if enum.is_cipher_suite}
        self.protocol = protocol
        self.cipher_suite = cipher_suite
        log.info(f"Parsing {self.cipher_suite}")

    def parse_cipher_suite(self):
        """
        Parse used cipher suite into python readable objects

        The cipher suite is split into each parameter and then sorted
        to categorize with the help of a json file. Categories are
        defined in PType.py class.
        """

        raw_parameters = self.cipher_suite.split("_")
        try:
            raw_parameters.remove("TLS")
            raw_parameters.remove("WITH")
        except ValueError:
            pass
        parameter_types = list(self.parameters.keys())
        # For each parameter iterate through each enum value until a match is found
        for p_raw in raw_parameters:
            for p_type in parameter_types:
                if p_raw in json_data[p_type.name].split(","):
                    parameter_types.remove(p_type)
                    log.debug(f"Found value for {p_type} parameter")
                    self.parameters[p_type] = {p_raw: 0}
                    break
        for p_type in list(self.parameters.keys()):
            # Check if parameter has no value
            if not self.parameters[p_type]:
                log.debug(f"No value for {p_type} parameter")
                self.parameters[p_type] = {"N/A": 0}

    def rate_cipher_suite(self):
        """
        Rate all cipher suite parameters
        """
        rateable_parameters = list(self.parameters.keys())
        key_types = [
            PType.sym_enc_algorithm_key_length,
            PType.sym_ecn_algorithm_block_mode_number,
        ]
        self.rate_parameters(rateable_parameters, key_types)

    def parse_protocol_version(self):
        """
        Read the protocol version and apply special edge cases
        """
        self.parameters[PType.protocol] = {self.protocol: 0}
        if self.protocol == "TLSv1":
            self.parameters[PType.protocol] = {"TLSv1.0": 0}
        if self.protocol == "TLSv1.3":
            log.debug(f"Setting {PType.kex_algorithm} as ECDHE for protocol TLSv1.3")
            self.parameters[PType.kex_algorithm] = {"ECDHE": 0}
