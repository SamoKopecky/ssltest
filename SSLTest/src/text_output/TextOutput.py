import logging

from ..utils import read_json

log = logging.getLogger(__name__)


def printn(string):
    print(string, end="")


class TextOutput:
    def __init__(self, address):
        self.address = address
        self.ratings = read_json('security_levels_names.json')
        self.english = read_json('english_strings.json')
        self.data = None

    def print_data(self, data):
        """
        Call all other text output functions for each port and url
        """
        log.info("Fomating output")
        self.data = data
        self.filter_data()
        self.write_title()
        self.recursive_print(self.data, 0)
        print()

    def filter_data(self):
        # TEMP:
        # self.data = next(iter(self.data.values()))
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
        else:
            printn(f": {data}")

    def print_parameters(self, data, indent):
        indent = indent + 1
        for k, v in data.items():
            printn("\n" + "\t" * indent + f"{self.english[k]}: ")
            if type(v) != dict:
                printn(v)
                continue
            printn(f"{next(iter(v.values()))}  ({next(iter(v.keys()))})")

    def print_address(self):
        print(f"scan for {self.address.url}:{self.address.port}")

    def write_title(self):
        pass
