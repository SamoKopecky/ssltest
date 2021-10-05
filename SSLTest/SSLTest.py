#!/usr/bin/env python3

__version__ = "0.0.2"

import argparse
import os
import subprocess
import sys

from ptlibs import ptjsonlib, ptmisclib

from src.run import run
from src.scan import get_tests_switcher


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
    tests_help = 'test the server for a specified vulnerability' \
                 'possible vulnerabilities (separate with spaces):\n'
    for key, value in get_tests_switcher().items():
        test_number = key
        test_desc = value[1]
        tests_help += f'{" " * 30}{test_number}: {test_desc}\n'
    tests_help += 'if this argument isn\'t specified all tests will be ran'
    return tests_help


def get_help():
    return [
        {"description": ["Script that scans web servers cryptographic parameters and vulnerabilities "]},
        {"usage": [f"{SCRIPTNAME}.py <options>"]},
        {"usage_example": [f"{SCRIPTNAME}.py -u https://example.com -t 1 2"]},
        {"options": [
            ["-u", "--url", "<url>", "Url to scan, required option"],
            ["-p", "--port", "<port ...>", "Port or ports (separate with spaces) to scan on (default: 443)"],
            ["-j", "--json", "<file>",
             "Change output to json format, if a file name is specified output is written to the given file"],
            ["-t", "--test", "<number ...>", get_tests_help()],
            ["-to", "--timeout", "<duration>", "Set a duration for the timeout of connections"],
            ["-cs", "--cipher-suites", "", "Scan all supported cipher suites by the server"],
            ["-fc", "--fix-conf", "", "Fix the /etc/ssl/openssl.cnf file to allow the use of older TLS protocols"
                                      " (TLSv1 and TLSv1.1)"],
            ["-st", "--sudo-tty", "", "Use the terminal prompt to enter the sudo password"],
            ["-ss", "--sudo-stdin", "", "Use the stdin of the script to enter the sudo password"],
            ["-ns", "--nmap-scan", "", "Use nmap to scan the server version"],
            ["-nd", "--nmap-discover", "", "Use nmap to discover web server ports"],
            ["-w", "--worst", "", "Create a main connection on the worst available protocol version, otherwise servers "
                                  "preferred protocol version is chosen"],
            ["-i", "--info", "", "Output some internal information about the script functions"],
            ["-d", "--debug", "", "Output debug information"],
            ["-v", "--version", "", "Show script version and exit"],
            ["-h", "--help", "", "Show this help message and exit"]
        ]}
    ]


def print_help():
    ptmisclib.help_print(get_help(), SCRIPTNAME, __version__)


def parse_args():
    parser = argparse.ArgumentParser(add_help=False, usage=f"{SCRIPTNAME}.py <options>")
    required = parser.add_argument_group("required arguments")
    fix_config = parser.add_mutually_exclusive_group()
    required.add_argument("-u", "--url", required=True, metavar="url")
    fix_config.add_argument("-st", "--sudo-tty", action="store_true", default=False)
    fix_config.add_argument("-ss", "--sudo-stdin", action="store_true", default=False)
    parser.add_argument("-p", "--port", default=[443], type=int, nargs="+", metavar="port")
    parser.add_argument("-j", "--json", action="store", metavar="output_file", required=False, nargs="?", default=False)
    parser.add_argument("-t", "--test", type=int, metavar="test_num", nargs="+")
    parser.add_argument("-to", "--timeout", type=int, nargs="?", default=1)
    parser.add_argument("-cs", "--cipher-suites", action="store_true", default=False)
    parser.add_argument("-ns", "--nmap-scan", action="store_true", default=False)
    parser.add_argument("-nd", "--nmap-discover", action="store_true", default=False)
    parser.add_argument("-fc", "--fix-conf", action="store_true", default=False)
    parser.add_argument("-w", "--worst", action="store_true", default=False)
    parser.add_argument("-i", "--info", action="store_true", default=False)
    parser.add_argument("-d", "--debug", action="store_true", default=False)
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")

    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        print_help()
        sys.exit(0)
    args = parser.parse_args()
    if not args.fix_conf and (args.sudo_tty or args.sudo_stdin):
        parser.error('argument -fc/--fix-conf needs to be used to use -st/--sudo-tty or -ss/--sudo-stdin')
    elif args.fix_conf and (not args.sudo_tty and not args.sudo_stdin):
        parser.error('argument -fc/--fix-conf needs -st/--sudo-tty or -ss/--sudo-stdin to be present')
    fix_conf_option(args)
    check_test_option(args.test)
    if '-j' not in sys.argv:
        ptmisclib.print_banner(SCRIPTNAME, __version__, args.json)
    return args


def fix_conf_option(args):
    """
    Fixes the OpenSSL configuration file

    :param Namespace args: Parsed input arguments
    """
    if args.fix_conf:
        if args.sudo_tty:
            try_to_remove_argument('-st', '--sudo-ttv')
            return_code = subprocess.run(
                ['sudo', '-k', '-p', '[sudo] password for %H to fix config file: ', './src/fix_openssl_config.py']
            ).returncode
        elif args.sudo_stdin:
            try_to_remove_argument('-ss', '--sudo-stdin')
            return_code = subprocess.run(['sudo', '-k', '-S', '-p', '', './src/fix_openssl_config.py']).returncode
        else:
            return_code = 1
        if return_code == 1:
            exit(1)
        try_to_remove_argument('-fc', '--fix-conf')
        # Restarts the program without the fc, st and ss arguments
        os.execl(sys.executable, os.path.abspath(__file__), *sys.argv)


def try_to_remove_argument(short_name, full_name):
    try:
        sys.argv.remove(short_name)
    except ValueError:
        sys.argv.remove(full_name)


def check_test_option(tests):
    if not tests:
        return
    tests_switcher = get_tests_switcher()
    test_numbers = [test for test in tests_switcher.keys()]
    unknown_tests = list(filter(lambda t: t not in test_numbers, tests))
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
