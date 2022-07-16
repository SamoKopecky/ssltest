import logging
import os
import shutil
import subprocess
import sys

from ptlibs import ptjsonlib, ptmisclib

from .run import run
from ..Args import Args, __version__
from ..vulnerabilities.TestRunner import TestRunner

script_name = "ssltest"

log = logging.getLogger(__name__)


class Script:
    def __init__(self, args):
        self.args = args
        self.ptjsonlib = ptjsonlib.ptjsonlib(self.args.json)
        self.json_no = self.ptjsonlib.add_json("ssltest")
        self.use_json = self.args.json

    def run(self):
        run(self.args)
        ptmisclib.ptprint(
            ptmisclib.out_if(self.ptjsonlib.get_all_json(), "", self.use_json)
        )


def get_tests_help():
    """
    Get all the tests in a ptlibs parsable way

    :return: List of tests
    :rtype: list[list[str, str, str, str]]
    """
    space_before = " " * 2
    tests = [[f"{space_before}0", "No tests", "", "Dont run any tests"]]
    for key, test_class in list(TestRunner.get_tests_switcher().items())[1:]:
        tests.append(
            [f"{space_before}{key}", test_class.short_name, "", test_class.description]
        )
    return tests


def get_usage():
    """
    Get script usage
    """
    return f"{script_name} <options>"


def get_help():
    """
    Get the print output
    """
    help_msg = [
        {
            "description": [
                "Script that scans web servers cryptographic parameters and vulnerabilities "
            ]
        },
        {"usage": [get_usage()]},
        {"usage_example": [f"{script_name} -u https://example.com -t 1 2"]},
        {
            "options": [
                ["-u", "--url", "<url>", "Url to scan, required option"],
                [
                    "-p",
                    "--port",
                    "<port ...>",
                    "Port or ports (separate with spaces) to scan on (default: 443)",
                ],
                [
                    "-j",
                    "--json",
                    "<file>",
                    "Change output to json format, if a file name is specified output is written to the given file",
                ],
                [
                    "-c",
                    "--config",
                    "<dir>",
                    "Custom config directory (absolute path), not all config files need to be present",
                ],
                [
                    "-t",
                    "--test",
                    "<num ...>",
                    "Run specified vulnerability tests (numbers) separated with spaces, "
                    "if unspecified all tests are ran",
                ],
            ]
        },
    ]
    help_msg[3]["options"].extend(get_tests_help())
    help_msg[3]["options"].extend(
        [
            ["-sn", "--short-names", "", "Limit alternative names to first 5"],
            [
                "-cc",
                "--cert-chain",
                "",
                "Get information about the whole certificate chain",
            ],
            [
                "-cs",
                "--cipher-suites",
                "",
                "Scan all supported cipher suites by the server",
            ],
            [
                "-fc",
                "--fix-conf",
                "",
                "Fix the /etc/ssl/openssl.cnf file to allow the use of older TLS protocols"
                " (TLSv1 and TLSv1.1), requires root privileges (see -st and -ss options)",
            ],
            [
                "-st",
                "--sudo-tty",
                "",
                "Use the terminal prompt to enter the sudo password",
            ],
            [
                "-ss",
                "--sudo-stdin",
                "",
                "Use the stdin of the script to enter the sudo password",
            ],
            ["-ns", "--nmap-scan", "", "Use nmap to scan the server version"],
            [
                "-nd",
                "--nmap-discover",
                "",
                "Use nmap to discover web server ports, requires root privileges,"
                " (see -st and -ss options)",
            ],
            [
                "-w",
                "--worst",
                "",
                "Create a main connection on the worst available protocol version, otherwise servers "
                "preferred protocol version is chosen",
            ],
            ["-i", "--info", "", "Enable logging at info level"],
            ["-d", "--debug", "", "Enable logging at debug level"],
            ["-v", "--version", "", "Show script version and exit"],
            ["-h", "--help", "", "Show this help message and exit"],
        ]
    )
    return help_msg


def print_help():
    """
    Print help output
    """
    ptmisclib.help_print(get_help(), script_name, __version__)


def custom_args_parse(args, parser):
    """
    Parse input arguments

    :param argparse.Namespace args: Parsed script arguments
    :param argparse.ArgumentParser parser: Parser from argparse
    :return: Parsed script arguments
    :rtype: argparse.Namespace
    """
    sudo_ops = Args.get_sudo_ops()

    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        print_help()
        sys.exit(0)

    if args.url is None:
        parser.error("the following arguments are required: -u/--url")

    error_string = (
        "option {error_option} needs "
        f'{sudo_ops["st"][2]} or {sudo_ops["ss"][2]} to be present'
    )

    if (args.sudo_tty or args.sudo_stdin) and not (args.nmap_discover or args.fix_conf):
        parser.error(
            f"options {sudo_ops['st'][2]} and {sudo_ops['ss'][2]} can only be used with {sudo_ops['fc'][2]} "
            f"or {sudo_ops['nd'][2]}"
        )
    elif not (args.sudo_tty or args.sudo_stdin):
        if args.fix_conf:
            parser.error(error_string.format(error_option=sudo_ops["fc"][2]))
        elif args.nmap_discover:
            parser.error(error_string.format(error_option=sudo_ops["nd"][2]))
    check_test_option(args.test, parser.format_usage())
    if "-j" not in sys.argv and "-fc" not in sys.argv:
        ptmisclib.print_banner(script_name, __version__, args.json)
    return args


def fix_conf_option(args):
    """
    Call a script to fix openssl config file

    :param argparse.Namespace args: Parsed script arguments
    """
    if args.fix_conf:
        log.info("Removing argument fc and running fix script")
        remove_argument("-fc", "--fix-conf")
        # Get the script path before it is ran as root
        script_path = shutil.which("fix_openssl_config.py")
        # Restarts the program without the fc, st and ss arguments
        logging.info("Running fix config script")
        return_code = subprocess.run(["sudo", script_path]).returncode
        if return_code == 1:
            log.critical("Fix script failed")
            exit(1)
        log.debug("Running main script again without root")
        os.execl(sys.executable, os.path.abspath(__file__), *sys.argv)


def make_root(args):
    """
    Make the user change to root permissions to run fix script or nmap

    :param argparse.Namespace args: Parsed script arguments
    """
    if not (args.sudo_tty or args.sudo_stdin):
        log.debug("No sudo option present, not running as root")
        return
    log.debug("Running as root")
    var_args = vars(args)
    reasons_switch = {"fix_conf": "to fix config file", "nmap_discover": "to use nmap"}
    reasons = [v for k, v in reasons_switch.items() if var_args[k]]
    reason_str = " and ".join(reasons)
    if args.sudo_tty:
        log.debug("Using console for password input")
        remove_argument("-st", "--sudo-ttv")
        return_code = subprocess.run(["sudo", "-S", "-p", "", "-v"]).returncode
    elif args.sudo_stdin:
        log.debug("Using stdin for password input")
        remove_argument("-ss", "--sudo-stdin")
        return_code = subprocess.run(
            ["sudo", "-p", f"[sudo] password for %u {reason_str}: ", "-v"]
        ).returncode
    else:
        return_code = 1
    if return_code == 1:
        log.critical("Error occurred when trying to run as root")
        exit(1)
    return return_code


def remove_argument(short_name, full_name):
    """
    Remove option from options

    :param str short_name: Short option
    :param str full_name: Long option
    """
    try:
        sys.argv.remove(short_name)
    except ValueError:
        sys.argv.remove(full_name)


def check_test_option(tests, usage):
    """
    Filter test option to check if test numbers are valid

    :param list[str] tests: Test numbers
    :param str usage: Script usage
    """
    if not tests:
        return
    tests_switcher = TestRunner.get_tests_switcher()
    test_numbers = [test for test in tests_switcher.keys()]
    unknown_tests = list(filter(lambda t: t not in test_numbers, tests))
    if unknown_tests:
        print(usage)
        if len(unknown_tests) > 1:
            unknown_tests = list(map(str, unknown_tests))
            print(
                f'Numbers {",".join(unknown_tests)} are not test numbers',
                file=sys.stderr,
            )
        else:
            print(
                f"Number {unknown_tests[0]}" f" is not a test number", file=sys.stderr
            )
        sys.exit(1)


def run_script(args, parser):
    """
    Run the script and start scanning

    :param argparse.Namespace args: Parsed script arguments
    :param argparse.ArgumentParser parser: Parser from argparse
    """
    args = custom_args_parse(args, parser)
    make_root(args)
    fix_conf_option(args)
    script = Script(args)
    script.run()
