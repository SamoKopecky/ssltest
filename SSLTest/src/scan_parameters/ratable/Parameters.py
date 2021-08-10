from abc import ABC

from ..utils import rate_key_length_parameter, rate_parameter


class Parameters(ABC):
    def __init__(self):
        self.parameters = {}
        self.rating = 0

    def rate_parameters(self, rateable_parameters, key_types):
        """
        Rate given parameters of PType class

        :param list rateable_parameters: Parameters to be rated
        :param list key_types: Key type parameters to be rated
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
        self.rating = self.get_worst_rating()

    def get_worst_rating(self):
        """
        Return the worse rating from all of the parameters

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
        Get the first key of an dictionary

        :param dict dictionary: Dictionary to get the key from
        :return: First key
        """
        return next(iter(dictionary))
