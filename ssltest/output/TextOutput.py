import logging
import re

from ptlibs.ptmisclib import get_colored_text, terminal_width

from ..core.utils import read_json
from ..sockets.SocketAddress import SocketAddress

log = logging.getLogger(__name__)


def printn(string):
    print(string, end="", flush=True)


class TextOutput:
    def __init__(self, address, args):
        """
        Constructor

        :param SocketAddress address: Webserver address
        """
        self.address = address
        self.english = read_json("english_strings.json")
        self.data = None
        self.category_title = ""
        self.address_filler = "="
        self.category_title_filter = "-"
        self.indent_start = 0
        self.short_names = args.short_names

    def __del__(self):
        print()

    def print_address(self):
        """
        Print the address of a scan
        """
        self.print_title(
            2, f"Scan for {self.address.url}:{self.address.port}", self.address_filler
        )

    def print_category(self, data):
        """
        Print json category data in a readable form

        :param dict data: Category data
        """
        log.info("Printing output")
        self.data = data
        self.filter_data(self.data)
        if not self.data:
            log.warning("No values found not printing output")
            return
        self.print_category_title()
        if self.category_title == "parameters":
            self.print_parameters(self.data, self.indent_start)
            return
        self.recursive_print(self.data, self.indent_start)

    def print_category_title(self):
        """
        Print the title of a category and remove it from the json data
        """
        title = next(iter(self.data.keys()))
        self.category_title = title
        self.data = self.data[title]

        print()
        self.print_title(
            (self.indent_start + 1) * 4, self.english[title], self.category_title_filter
        )

    def recursive_print(self, data, indent):
        """
        Recursively print json data

        :param dict or str or list data: Data to be printed
        :param int indent: Indentation count
        """
        indent += 1
        if type(data) == dict:
            for key, value in data.items():
                key = self.smart_map(key)
                printn("\n" + "\t" * indent + key)
                self.recursive_print(value, indent)
        elif type(data) == list:
            if len(data) == 1:
                printn(f": {data[0]}")
                return
            for value in data:
                printn("\n" + "\t" * indent + value)
        elif type(data) == tuple:
            row = " ".join(map(self.get_color_for_value, data))
            printn(": " + row)
        else:
            printn(f": {self.get_color_for_value(data)}")

    def print_parameters(self, data, indent):
        """
        Print parameters data

        :param dict data: Data to be printed
        :param int indent: Indentation count
        """
        indent += 1
        for key, value in data.items():
            key = self.smart_map(key)
            printn("\n" + "\t" * indent + f"{key}: ")
            if type(value) != dict:
                printn(self.get_color_for_value(value))
                continue
            printn(
                f"{self.get_color_for_value(next(iter(value.values())))} -- {next(iter(value.keys()))}"
            )

    def smart_map(self, key):
        """
        Map a key to its english equivalent including numbers

        :param str key: Key to be mapped
        :return: Mapped key
        :rtype: str
        """
        if key in self.english.keys():
            return self.english[key]
        elif re.search(".*_\d$", key):
            return f"{self.english[key[:-2]]} #{int(key[-1]) + 1}"
        return key

    @staticmethod
    def print_title(prefix_len, title_string, padding_char):
        """
        Print string title with the TITLE color with character padding

        Surround the title with padding characters, where the prefix length
        can be chosen and the suffix characters are filled so that the title
        takes up the whole terminal width.

        :param int prefix_len: Number of prefix characters
        :param str title_string: Title to be printed
        :param str padding_char: Padding character
        """
        title = f"{padding_char * prefix_len} {title_string} "
        try:
            width = terminal_width() - len(title)
            printn(get_colored_text(title + padding_char * width, "TITLE"))
        except OSError:
            print(title)

    def filter_data(self, data):
        """
        Removes any empty/invalid values/lists from the data

        :param dict list data: Data to be filtered
        """
        for key, value in list(data.items()):
            val_type = type(value)
            if (
                self.short_names
                and val_type is list
                and key is "cert_alternative_names"
            ):
                data[key] = TextOutput.shorted_alternative_names(value)
                continue
            if val_type is not dict:
                continue
            if not data[key]:
                del data[key]
                continue
            # index 0 cause of parameters dict
            keys_list = list(value.keys())
            if len(keys_list) > 0 and keys_list[0] == "N/A":
                del data[key]
                continue
            self.filter_data(value)

    @staticmethod
    def shorted_alternative_names(alternative_names):
        """
        Shorten the alternative names of a certificate

        :param list[str] alternative_names: Certificates alternative names
        :return: Certificates alternative names
        :rtype: list[str]
        """
        max_names = 5
        if len(alternative_names) < max_names:
            return alternative_names
        return alternative_names[:max_names] + ["..."]

    @staticmethod
    def get_color_for_value(text):
        """
        Surround the text with the appropriate ascii color characters

        :param str or bool text: Value to be colored
        :return: Colored string
        :rtype: str
        """
        bool_switcher = {True: "ERROR", False: "OK"}
        int_switcher = {1: "OK", 2: "TITLE", 3: "ERROR", 4: "ERROR"}
        if type(text) == bool:
            return get_colored_text(text, bool_switcher[text])
        elif text.isdigit():
            return get_colored_text(text, int_switcher[int(text)])
        else:
            return text
