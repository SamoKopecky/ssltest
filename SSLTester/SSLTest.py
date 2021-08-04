#!/usr/bin/python3

__version__ = "0.0.1"

from ptlibs import ptjsonlib, ptmisclib
import argparse
import sys

from src.start_script import start


class SSLTester:
    def __init__(self, args):
        self.args = args
        self.ptjsonlib = ptjsonlib.ptjsonlib(self.args.json)
        self.json_no = self.ptjsonlib.add_json("SSLTester")
        self.use_json = self.args.json

    def run(self):
        start(self.args)
        ptmisclib.ptprint(ptmisclib.out_if(self.ptjsonlib.get_all_json(), "", self.use_json))


def get_help():
    return [
        {"description": ["Script that scans a webservers cryptographic parameters and vulnerabilities"]},
        {"usage": [
            "SSLTester.py -u url <-h> <-ns> <-nd> <-p port <port ...>> <-j <output_file>> <-t test_num <test_num ...>>"
            " <-fc> <-i> <-v>"
        ]},
        {"usage_example": [
            "SSLTester.py -u github.com -t 1 2",
        ]},
        {"options": [
            ["-u", "--url", "<url>", "Url to scan, required option"],
            ["-p", "--proxy", "<proxy>", "Set proxy (e.g. http://127.0.0.1:8080)"],
            ["-c", "--cookie", "<cookie=value>", "Set cookie(s)"],
            ["-H", "--headers", "<header:value>", "Set custom headers"],
            ["-ua", "--user-agent", "<user-agent>", "Set user agent"],
            ["-j", "--json", "", "Output in JSON format"],
            ["-v", "--version", "", "Show script version and exit"],
            ["-h", "--help", "", "Show this help message and exit"]
        ]
        }]


def parse_args():
    parser = argparse.ArgumentParser(add_help=False, usage=f"{SCRIPTNAME} <options>")
    required = parser.add_argument_group('required arguments')
    required.add_argument('-u', '--url', required=True, metavar='url')
    parser.add_argument('-ns', '--nmap-scan', action='store_true', default=False)
    parser.add_argument('-nd', '--nmap-discover', action='store_true', default=False)
    parser.add_argument('-p', '--port', default=[443], type=int, nargs='+', metavar='port')
    parser.add_argument('-j', '--json', action='store', metavar='output_file', required=False, nargs='?', default=False)
    parser.add_argument('-t', '--test', type=int, metavar='test_num', nargs='+')
    parser.add_argument('-fc', '--fix-conf', action='store_true', default=False)
    parser.add_argument('-d', '--debug', action='store_true', default=False)
    parser.add_argument('-i', '--info', action='store_true', default=False)
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")

    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        ptmisclib.help_print(get_help(), SCRIPTNAME, __version__)
        sys.exit(0)
    args = parser.parse_args()
    ptmisclib.print_banner(SCRIPTNAME, __version__, args.json)
    return args


def main():
    global SCRIPTNAME
    SCRIPTNAME = "SSLTester"
    args = parse_args()
    script = SSLTester(args)
    script.run()


if __name__ == "__main__":
    main()
