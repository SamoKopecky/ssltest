from scan_web_server.utils import *
from abc import ABC


class Parameters(ABC):
    def __init__(self):
        self.parameters = {}
        self.rating = 0

    def rate_parameters(self, rateable_parameters, key_types):
        """
        Rate all cipher suite parameters.

        First part is used if a length parameter needs to be rated
        Second part is used for not length parameters
        """
        for p_type in rateable_parameters:
            parameter = get_first_key(self.parameters[p_type])
            # 1st part
            if p_type in key_types:
                self.parameters[p_type][parameter] = rate_key_length_parameter(
                    get_first_key(self.parameters[p_type.key_pair]),
                    parameter, p_type
                )
                continue
            # 2nd part
            self.parameters[p_type][parameter] = rate_parameter(p_type, parameter)
        self.rating = self.get_max_rating()

    def get_max_rating(self):
        """
        Returns the worse rating from all of the parameters.
        """
        values = []
        for dicts in self.parameters.values():
            for value in dicts.values():
                values.append(value)
        return max(values)
