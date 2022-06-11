__version__ = '0.1.1'

import argparse
import logging
import os
import subprocess
import shutil
import sys

from importlib.resources import path
from ptlibs import ptjsonlib, ptmisclib

from .run import run
from ..vulnerabilities.TestRunner import TestRunner

script_name = 'ssltest'


class Script:
    def __init__(self, args):
        self.args = args
        self.ptjsonlib = ptjsonlib.ptjsonlib(self.args.json)
        self.json_no = self.ptjsonlib.add_json('ssltest')
        self.use_json = self.args.json

    def run(self):
        run(self.args)
        ptmisclib.ptprint(ptmisclib.out_if(
            self.ptjsonlib.get_all_json(), '', self.use_json))


def get_tests_help():
    space_before = ' ' * 2
    tests = [[f'{space_before}0', 'No tests', '', 'Dont run any tests']]
    for key, test_class in list(TestRunner.get_tests_switcher().items())[1:]:
        tests.append(
            [f'{space_before}{key}', test_class.short_name, '', test_class.description])
    return tests


def get_usage():
    return f'{script_name}.py <options>'


def get_help():
    help_msg = [
        {'description': [
            'Script that scans web servers cryptographic parameters and vulnerabilities ']},
        {'usage': [get_usage()]},
        {'usage_example': [f'{script_name}.py -u https://example.com -t 1 2']},
        {'options': [
            ['-u', '--url', '<url>', 'Url to scan, required option'],
            ['-p', '--port', '<port ...>',
             'Port or ports (separate with spaces) to scan on (default: 443)'],
            ['-j', '--json', '<file>',
             'Change output to json format, if a file name is specified output is written to the given file'],
            ['-t', '--test', '<num ...>',
             'Run specified vulnerability tests (numbers) separated with spaces, if unspecified all tests are ran'],
        ]}]
    help_msg[3]['options'].extend(get_tests_help())
    help_msg[3]['options'].extend([
        ['-to', '--timeout', '<dur>',
         'Set a duration for the timeout of connections in seconds'],
        ['-sc', '--short-cert', '', 'Limit alternative names to first 5'],
        ['-cs', '--cipher-suites', '', 'Scan all supported cipher suites by the server'],
        ['-fc', '--fix-conf', '', 'Fix the /etc/ssl/openssl.cnf file to allow the use of older TLS protocols'
                                  ' (TLSv1 and TLSv1.1), requires root privileges (see -st and -ss options)'],
        ['-st', '--sudo-tty', '', 'Use the terminal prompt to enter the sudo password'],
        ['-ss', '--sudo-stdin', '',
         'Use the stdin of the script to enter the sudo password'],
        ['-ns', '--nmap-scan', '', 'Use nmap to scan the server version'],
        ['-nd', '--nmap-discover', '', 'Use nmap to discover web server ports, requires root privileges,'
                                       ' (see -st and -ss options)'],
        ['-w', '--worst', '', 'Create a main connection on the worst available protocol version, otherwise servers '
                              'preferred protocol version is chosen'],
        ['-l', '--logging', '', 'Enable logging'],
        ['-d', '--debug', '', 'Log debug information'],
        ['-v', '--version', '', 'Show script version and exit'],
        ['-h', '--help', '', 'Show this help message and exit']
    ])
    return help_msg


def print_help():
    ptmisclib.help_print(get_help(), script_name, __version__)


def parse_args():
    sudo_ops = {
        'fc': ['-fc', '--fix-conf'],
        'nd': ['-nd', '--nmap-discover'],
        'ss': ['-ss', '--sudo-stdin'],
        'st': ['-st', '--sudo-tty'],
    }
    for key in sudo_ops.keys():
        sudo_ops[key].append('/'.join(sudo_ops[key]))

    parser = argparse.ArgumentParser(add_help=False)
    required = parser.add_argument_group('required arguments')
    fix_config = parser.add_mutually_exclusive_group()
    required.add_argument('-u', '--url', required=True, metavar='url')
    parser.add_argument('-h', '--help', action='store_true', default=False)
    parser.add_argument(
        '-p', '--port', default=[443], type=int, nargs='+', metavar='port')
    parser.add_argument('-j', '--json', action='store',
                        metavar='output_file', required=False, nargs='?', default=False)
    parser.add_argument('-t', '--test', type=int,
                        metavar='test_num', nargs='+')
    parser.add_argument('-to', '--timeout', type=int,
                        metavar='timeout', nargs='?', default=1)
    parser.add_argument('-sc', '--short-cert',
                        action='store_true', default=False)
    parser.add_argument('-cs', '--cipher-suites',
                        action='store_true', default=False)
    parser.add_argument('-ns', '--nmap-scan',
                        action='store_true', default=False)
    parser.add_argument(sudo_ops['nd'][0], sudo_ops['nd']
                        [1], action='store_true', default=False)
    parser.add_argument(sudo_ops['fc'][0], sudo_ops['fc']
                        [1], action='store_true', default=False)
    fix_config.add_argument(
        sudo_ops['st'][0], sudo_ops['st'][1], action='store_true', default=False)
    fix_config.add_argument(
        sudo_ops['ss'][0], sudo_ops['ss'][1], action='store_true', default=False)
    parser.add_argument('-w', '--worst', action='store_true', default=False)
    parser.add_argument('-l', '--logging', action='store_true', default=False)
    parser.add_argument('-d', '--debug', action='store_true', default=False)
    parser.add_argument('-v', '--version', action='version',
                        version=f'%(prog)s {__version__}')

    if len(sys.argv) == 1 or '-h' in sys.argv or '--help' in sys.argv:
        print_help()
        sys.exit(0)
    args = parser.parse_args()

    error_string = 'option {error_option} needs ' + \
                   f'{sudo_ops["st"][2]} or {sudo_ops["ss"][2]} to be present'

    if (args.sudo_tty or args.sudo_stdin) and not (args.nmap_discover or args.fix_conf):
        parser.error(f"options {sudo_ops['st'][2]} and {sudo_ops['ss'][2]} can only be used with {sudo_ops['fc'][2]} "
                     f"or {sudo_ops['nd'][2]}")
    elif not (args.sudo_tty or args.sudo_stdin):
        if args.fix_conf:
            parser.error(error_string.format(error_option=sudo_ops['fc'][2]))
        elif args.nmap_discover:
            parser.error(error_string.format(error_option=sudo_ops['nd'][2]))
    check_test_option(args.test, parser.format_usage())
    if '-j' not in sys.argv and '-fc' not in sys.argv:
        ptmisclib.print_banner(script_name, __version__, args.json)
    return args


def fix_conf_option(args):
    """
    Fixes the OpenSSL configuration file

    :param Namespace args: Parsed input arguments
    """
    if args.fix_conf:
        remove_argument('-fc', '--fix-conf')
        # Get the script path before it is ran as root
        script_path = shutil.which('fix_openssl_config.py')
        # Restarts the program without the fc, st and ss arguments
        logging.info('Running fix config script')
        return_code = subprocess.run(
            ['sudo', script_path]).returncode
        if return_code == 1:
            exit(1)
        os.execl(sys.executable, os.path.abspath(__file__), *sys.argv)


def make_root(args):
    if not (args.sudo_tty or args.sudo_stdin):
        return
    var_args = vars(args)
    reasons_switch = {
        'fix_conf': 'to fix config file',
        'nmap_discover': 'to use nmap'
    }
    reasons = [v for k, v in reasons_switch.items() if var_args[k]]
    reason_str = ' and '.join(reasons)
    if args.sudo_tty:
        remove_argument('-st', '--sudo-ttv')
        return_code = subprocess.run(['sudo', '-S', '-p', '', '-v']).returncode
    elif args.sudo_stdin:
        remove_argument('-ss', '--sudo-stdin')
        return_code = subprocess.run(
            ['sudo', '-p', f'[sudo] password for %u {reason_str}: ', '-v']).returncode
    else:
        return_code = 1
    if return_code == 1:
        exit(1)
    return return_code


def remove_argument(short_name, full_name):
    try:
        sys.argv.remove(short_name)
    except ValueError:
        sys.argv.remove(full_name)


def logging_option(args):
    """
    Handle the debug and information options

    :param Namespace args: Parsed input arguments
    """
    logger = logging.getLogger(__package__)
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    if args.debug:
        ch.setLevel(logging.DEBUG)
    elif args.logging:
        ch.setLevel(logging.INFO)
    else:
        logging.disable(sys.maxsize)
    formatter = logging.Formatter(
        '%(asctime)s [%(levelname)s] %(name)s: %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)


def check_test_option(tests, usage):
    if not tests:
        return
    tests_switcher = TestRunner.get_tests_switcher()
    test_numbers = [test for test in tests_switcher.keys()]
    unknown_tests = list(filter(lambda t: t not in test_numbers, tests))
    if unknown_tests:
        print(usage)
        if len(unknown_tests) > 1:
            unknown_tests = list(map(str, unknown_tests))
            print(f'Numbers {",".join(unknown_tests)} are not test numbers',
                  file=sys.stderr)
        else:
            print(f'Number {unknown_tests[0]}'
                  f' is not a test number', file=sys.stderr)
        sys.exit(1)


def run_script():
    args = parse_args()
    logging_option(args)
    make_root(args)
    fix_conf_option(args)
    script = Script(args)
    script.run()
