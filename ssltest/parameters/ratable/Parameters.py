import logging
from abc import ABC

from .PType import PType
from ...core.utils import read_json

security_levels_json = read_json("security_levels.json")
log = logging.getLogger(__name__)


class Parameters(ABC):
    def __init__(self):
        """
        Constructor
        """
        self.parameters = {}
        self.rating = 0

    def rate_parameters(self, rateable_parameters, key_types):
        """
        Rate given parameters of PType class

        :param list[PType] rateable_parameters: Parameters to be rated
        :param list[PType] key_types: Key type parameters to be rated
        """
        for p_type in rateable_parameters:
            log.debug(f"Rating {p_type} parameter")
            parameter = self.key(self.parameters[p_type])
            # length parameters
            if p_type in key_types:
                self.parameters[p_type][parameter] = self.rate_key_length_parameter(
                    self.key(self.parameters[p_type.key_pair]), parameter, p_type
                )
                continue
            # normal parameters
            self.parameters[p_type][parameter] = self.rate_parameter(p_type, parameter)
        self.rating = self.get_worst_rating()

    def get_worst_rating(self):
        """
        Return the worse rating from all the parameters

        :return: Worst rating
        :rtype: int
        """
        values = []
        for dicts in self.parameters.values():
            for value in dicts.values():
                values.append(value)
        return max(values)

    @staticmethod
    def key(dictionary):
        """
        Get the first key of a dictionary

        :param dict dictionary: Dictionary to get the key from
        :return: First key
        """
        return next(iter(dictionary))

    @staticmethod
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
            "==": lambda a, b: a == b,
        }
        # TODO: All of the algorithms are not yet added to the security_levels.json
        levels_str = security_levels_json[key_len_type.name]
        if key_len == "N/A":
            return "0"
        for idx in range(1, 5):
            levels = levels_str[str(idx)].split(",")
            if algorithm_type in levels:
                # gets the operation assigned to the algorithm key length
                operation = levels[levels.index(algorithm_type) + 1]
                function = functions[operation[:2]]
                if function(int(key_len), int(operation[2:])):
                    return str(idx)
        return "0"

    @staticmethod
    def rate_parameter(p_type, parameter):
        """
        Rate a parameter using a defined json file

        :param PType p_type: Specifies which parameter category should be used for rating
        :param str parameter: Parameter that is going to be rated
        :return: Rating of the parameter else 0
        :rtype: str
        """
        # TODO: All of the algorithms are not yet added to the security_levels.json

        if parameter == "N/A":
            return "0"
        for idx in range(1, 5):
            if parameter in security_levels_json[p_type.name][str(idx)].split(","):
                return str(idx)
        return "0"

    @staticmethod
    def get_params_json(cipher_suite, certificate):
        """
        Get all ratable parameters json
        :param ssltest.parameters.ratable.CipherSuite.CipherSuite cipher_suite: Cipher suite
        :param ssltest.parameters.ratable.Certificate.Certificate certificate: Certificate
        :return: Json of ratable parameters
        :rtype: dict
        """
        worst_rating = max([cipher_suite.rating, certificate.rating])
        parameters = {key.name: value for key, value in cipher_suite.parameters.items()}
        for key, value in certificate.first_cert_parameters.items():
            if key == PType.cert_pub_key_algorithm and not parameters[key.name] == {
                "N/A": "0"
            }:
                continue
            if len(certificate.other_certs_parameters) == 0:
                parameters.update({f"{key.name}": value})
            else:
                parameters.update({f"{key.name}_0": value})
        for i, cert in enumerate(certificate.other_certs_parameters):
            for key, value in cert.items():
                parameters.update({f"{key.name}_{i + 1}": value})

        parameters.update({"rating": worst_rating})
        return parameters
