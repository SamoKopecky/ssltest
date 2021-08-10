#!/usr/bin/python3

__version__ = "0.0.1"

import argparse
import sys

from ptlibs import ptjsonlib, ptmisclib

from src.run import run, get_tests_switcher


class SSLTest:
    def __init__(self, args):
        self.args = args
        self.ptjsonlib = ptjsonlib.ptjsonlib(self.args.json)
        self.json_no = self.ptjsonlib.add_json("SSLTest")
        self.use_json = self.args.json

    def run(self):
        run(self.args)
        ptmisclib.ptprint(ptmisclib.out_if(self.ptjsonlib.get_all_json(), "", self.use_json))


def get_tests_help():
    tests_help = 'test the server for a specified vulnerability\n' \
                 'possible vulnerabilities (separate with spaces):\n'
    for key, value in get_tests_switcher().items():
        test_number = key
        test_desc = value[1]
        tests_help += f'{" " * 4}{test_number}: {test_desc}\n'
    tests_help += 'if this argument isn\'t specified all tests will be ran'
    return tests_help


def get_help():
    return [
        {"description": ["Script that scans web servers cryptographic parameters and vulnerabilities "]},
        {"usage": [f"{SCRIPTNAME}.py <options>"]},
        {"usage_example": [f"{SCRIPTNAME}.py -u https://example.com -t 1 2"]},
        {"options": [
            ["-u", "--url", "<url>", "Url to scan, required option"],
            ["-p", "--port", "<port ...>", "Port or ports (separate with spaces) to scan on (default: [443])"],
            ["-j", "--json", "<file>",
             "change output to json format, if a file name is specified output is written to the given file"],
            ["-t", "--test", "<number ...>", get_tests_help()],
            ["-fc", "--fix-conf", "", "Allow the use of older versions of TLS protocol (TLSv1 and TLSv1.1) in order to"
                                      "\n scan a server which still run on these versions. !WARNING!: this may rewrite"
                                      "\n the contents of a configuration file located at /etc/ssl/openssl.cnf"],
            ["-ns", "--nmap-scan", "", "Use nmap to scan the server version"],
            ["-nd", "--nmap-discover", "", "Use nmap to discover web server ports"],
            ["-i", "--info", "", "Output some internal information about the script functions"],
            ["-d", "--debug", "", "Output debug information"],
            ["-v", "--version", "", "Show script version and exit"],
            ["-h", "--help", "", "Show this help message and exit"]
        ]
        }
    ]


def print_help():
    ptmisclib.help_print(get_help(), SCRIPTNAME, __version__)


def parse_args():
    parser = argparse.ArgumentParser(add_help=False, usage=f"{SCRIPTNAME}.py <options>")
    required = parser.add_argument_group("required arguments")
    required.add_argument("-u", "--url", required=True, metavar="url")
    parser.add_argument("-p", "--port", default=[443], type=int, nargs="+", metavar="port")
    parser.add_argument("-j", "--json", action="store", metavar="output_file", required=False, nargs="?", default=False)
    parser.add_argument("-t", "--test", type=int, metavar="test_num", nargs="+")
    parser.add_argument("-fc", "--fix-conf", action="store_true", default=False)
    parser.add_argument("-ns", "--nmap-scan", action="store_true", default=False)
    parser.add_argument("-nd", "--nmap-discover", action="store_true", default=False)
    parser.add_argument("-i", "--info", action="store_true", default=False)
    parser.add_argument("-d", "--debug", action="store_true", default=False)
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")

    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        print_help()
        sys.exit(0)
    args = parser.parse_args()
    check_test_option(args.test)
    if '-j' not in sys.argv:
        ptmisclib.print_banner(SCRIPTNAME, __version__, args.json)
    return args


def check_test_option(tests):
    """
    Check if the tests numbers are actually tests

    :param tests: test argument
    :return:
    """
    if not tests:
        return
    tests_switcher = get_tests_switcher()
    test_numbers = [test for test in tests_switcher.keys()]
    unknown_tests = list(filter(lambda test: test not in test_numbers, tests))
    if unknown_tests:
        print_help()
        if len(unknown_tests) > 1:
            unknown_tests = list(map(str, unknown_tests))
            print(f"Numbers {','.join(unknown_tests)} are not test numbers.", file=sys.stderr)
        else:
            print(f"Number {unknown_tests[0]} is not a test number.", file=sys.stderr)
        sys.exit(1)


def main():
    global SCRIPTNAME
    SCRIPTNAME = "SSLTest"
    args = parse_args()
    script = SSLTest(args)
    script.run()


if __name__ == "__main__":
    main()
