import json
import logging

from ..utils import read_json

log = logging.getLogger(__name__)


def printn(string):
    print(string, end="")


class TextOutput:
    def __init__(self, data: dict):
        self.output = ''
        self.ratings = read_json('security_levels_names.json')
        self.english = read_json('english_strings.json')
        self.data = data

    def get_formatted_text(self):
        """
        Call all other text output functions for each port and url
        """
        log.info("Fomating output")
        self.filter_data()
        self.recursive_print(self.data, -1)
        print()

    def filter_data(self):
        # TEMP:
        self.data = next(iter(self.data.values()))
        pass

    def recursive_print(self, data, indent):
        indent += 1
        if type(data) == dict:
            for k, v in data.items():
                if k in self.english:
                    k = self.english[k]
                printn("\n" + "\t" * indent + k)
                if k == 'Parameters':
                    self.print_parameters(v, indent)
                    continue
                self.recursive_print(v, indent)
        elif type(data) == list:
            if len(data) == 1:
                printn(f": {data[0]}")
                return
            for v in data:
                printn(":\n" + "\t" * indent + v)
        elif type(data) != dict and type(data) != list:
            printn(f": {data}")

    @staticmethod
    def print_parameters(data, indent):
        indent = indent + 1
        for k, v in data.items():
            printn("\n" + "\t" * indent + f"{k}: ")
            if type(v) != dict:
                printn(v)
                continue
            printn(f"{next(iter(v.values()))}  ({next(iter(v.keys()))})")
