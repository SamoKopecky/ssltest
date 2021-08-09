from abc import ABC

from ..utils import rate_key_length_parameter, rate_parameter


class Parameters(ABC):
    def __init__(self):
        self.parameters = {}
        self.rating = 0

    def rate_parameters(self, rateable_parameters: list, key_types: list):
        """
        Rate the parameters from the ratable_parameters list.
        """
        for p_type in rateable_parameters:
            parameter = self.key(self.parameters[p_type])
            # length parameters
            if p_type in key_types:
                self.parameters[p_type][parameter] = rate_key_length_parameter(
                    self.key(self.parameters[p_type.key_pair]),
                    parameter, p_type
                )
                continue
            # normal parameters
            self.parameters[p_type][parameter] = rate_parameter(p_type, parameter)
        self.rating = self.get_max_rating()

    def get_max_rating(self):
        """
        Return the worse rating from all of the parameters.
        """
        values = []
        for dicts in self.parameters.values():
            for value in dicts.values():
                values.append(value)
        return max(values)

    @staticmethod
    def key(dictionary: dict):
        return next(iter(dictionary))
