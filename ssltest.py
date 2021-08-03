#!/usr/bin/python3

import argparse, sys, logging, json, textwrap, traceback, os

from scan_vulnerabilities.tests import heartbleed
from scan_vulnerabilities.tests import ccs_injection
from scan_vulnerabilities.tests import insec_renegotiation as rene
from scan_vulnerabilities.tests import poodle
from scan_vulnerabilities.tests import session_ticket
from scan_vulnerabilities.tests import crime
from scan_vulnerabilities.tests import rc4_support
from ssl_scan.SSLv3 import SSLv3
from scan_parameters.ratable.CipherSuite import CipherSuite
from scan_parameters.ratable.Certificate import Certificate
from scan_parameters.non_ratable.ProtocolSupport import ProtocolSupport
from scan_parameters.non_ratable.WebServerSoft import WebServerSoft
from scan_parameters.connection.connection_utils import get_website_info
from scan_parameters.non_ratable.port_discovery import discover_ports
from scan_parameters.ratable.PType import PType
from scan_parameters.utils import fix_url
from text_output.TextOutput import TextOutput
from scan_vulnerabilities.multitheard_scan import scan_vulnerabilities
from fix_openssl_config import fix_openssl_config

tests_switcher = {
    1: (heartbleed.scan, 'Heartbleed'),
    2: (ccs_injection.scan, 'CCS injection'),
    3: (rene.scan, 'Insecure renegotiation'),
    4: (poodle.scan, 'ZombiePOODLE/GOLDENDOOLDE'),
    5: (session_ticket.scan, 'Session ticket support'),
    6: (crime.scan, 'CRIME'),
    7: (rc4_support.scan, 'RC4 support')
}


def tls_test(program_args):
    args = parse_options(program_args)
    fix_conf_option(args)
    if '/' in args.url:
        args.url = fix_url(args.url)
    info_report_option(args)
    nmap_discover_option(args)
    output_data = scan_all_ports(args)
    return json_option(args, output_data)


def fix_conf_option(args):
    """
    Fixes the OpenSSL configuration file

    :param args: input options
    """
    if args.fix_conf:
        try:
            fix_openssl_config()
        except PermissionError:
            print("Permission denied can't write to OpenSSL config file", file=sys.stderr)
            exit(1)
        sys.argv.remove('-fc')
        # Restarts the program without the fc argument
        os.execl(sys.executable, os.path.abspath(__file__), *sys.argv)


def vulnerability_scan(address, tests, version):
    """
    Forwards the appropriate tests to multithreading function

    :param version: ssl protocol version
    :param address: tuple of an url and port
    :param tests: input option for tests
    :return: dictionary of scanned results
    """
    # if no -t argument is present
    if not tests:
        scans = [value for value in tests_switcher.values()]
    elif 0 in tests:
        return {}
    else:
        scans = [tests_switcher.get(test) for test in tests]
    return scan_vulnerabilities(scans, address, version)


def json_option(args, output_data):
    """
    Handle output depending on the input options

    :param args: input options
    :param output_data: json data to output
    """
    json_output_data = json.dumps(output_data, indent=2)
    if args.json is False:
        text_output = TextOutput(json_output_data)
        text_output.text_output()
        return text_output.output
    elif args.json is None:
        return json_output_data
    else:
        file = open(args.json, 'w')
        file.write(json_output_data)
        file.close()


def scan_all_ports(args):
    """
    Call scan function for each port

    :param args: input options
    :return: dictionary of scanned data
    """
    output_data = {}
    for port in args.port:
        try:
            output_data.update(scan(args, port))
        except Exception as ex:
            tb = traceback.format_exc()
            logging.debug(tb)
            print(f'Unexpected exception occurred: {ex}', file=sys.stderr)
    return output_data


def nmap_discover_option(args):
    """
    Discover usable ports

    :param args: input options
    """
    scanned_ports = []
    if args.nmap_discover:
        try:
            scanned_ports = discover_ports(args.url)
        except Exception as ex:
            tb = traceback.format_exc()
            logging.debug(tb)
            print(f'Unexpected exception occurred: {ex}', file=sys.stderr)
        scanned_ports = list(filter(lambda port: port not in args.port, scanned_ports))
        args.port.extend(scanned_ports)


def info_report_option(args):
    """
    Handle verbose and information option

    :param args: input options
    """
    if args.verbose:
        logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    elif args.information:
        logging.basicConfig(stream=sys.stderr, level=logging.INFO)


def parse_options(program_args):
    """
    Parse input options.

    :return: object of parsed arguments
    """
    tests_help = 'test the server for a specified vulnerability\n' \
                 'possible vulnerabilities (separate with spaces):\n'
    for key, value in tests_switcher.items():
        test_number = key
        test_desc = value[1]
        tests_help += f'{" " * 4}{test_number}: {test_desc}\n'
    tests_help += 'if this argument isn\'t specified all tests will be ran\n' \
                  'if 0 is given as a test number no tests will be ran'

    parser = argparse.ArgumentParser(
        usage='use -h or --help for more information',
        description='Script that scans a webservers cryptographic parameters and vulnerabilities',
        formatter_class=argparse.RawTextHelpFormatter)
    required = parser.add_argument_group('required arguments')
    required.add_argument('-u', '--url', required=True, metavar='url', help='url to scan')
    parser.add_argument('-ns', '--nmap-scan', action='store_true', default=False,
                        help='use nmap to scan the server version')
    parser.add_argument('-nd', '--nmap-discover', action='store_true', default=False,
                        help='use nmap to discover web server ports')
    parser.add_argument('-p', '--port', default=[443], type=int, nargs='+', metavar='port',
                        help='port or ports (separate with spaces) to scan on (default: %(default)s)')
    parser.add_argument('-j', '--json', action='store', metavar='output_file', required=False,
                        nargs='?', default=False,
                        help=textwrap.dedent('''\
                        change output to json format, if a file name is specified 
                        output is written to the given file 
                        '''))
    parser.add_argument('-t', '--test', type=int, metavar='test_num', nargs='+',
                        help=textwrap.dedent(tests_help))
    parser.add_argument('-fc', '--fix-conf', action='store_true', default=False,
                        help=textwrap.dedent('''\
                        allow the use of older versions of TLS protocol
                        (TLSv1 and TLSv1.1) in order to scan a server which 
                        still run on these versions.
                        !WARNING!: this may rewrite the contents of a 
                        configuration file located at /etc/ssl/openssl.cnf
                        backup is recommended, root permission required
                            '''))
    parser.add_argument('-i', '--information', action='store_true', default=False, help='output some information')
    parser.add_argument('-v', '--verbose', action='store_true', default=False, help='output more information')

    args = parser.parse_args(program_args)
    check_test_numbers(args.test, parser.usage)
    return args


def check_test_numbers(tests, usage):
    """
    Check if the tests numbers are actually tests
    
    :param tests: test argument
    :param usage: usage string
    :return: 
    """
    if not tests or 0 in tests:
        return
    test_numbers = [test for test in tests_switcher.keys()]
    unknown_tests = list(filter(lambda test: test not in test_numbers, tests))
    if unknown_tests:
        print(f'usage: {usage}')
        if len(unknown_tests) > 1:
            unknown_tests = list(map(str, unknown_tests))
            print(f'Numbers {", ".join(unknown_tests)} are not test numbers.', file=sys.stderr)
        else:
            print(f'Number {unknown_tests[0]} is not a test number.', file=sys.stderr)
        exit(1)


def scan(args, port: int):
    """
    Call other scanning functions for a specific url and port

    :param args: parsed arguments
    :param port: list of port to be scanned
    :return: a single dictionary containing scanned data
    """
    logging.info(f'Scanning for {args.url}:{port}')
    certificate, cert_verified, cipher_suite, protocol = get_website_info(args.url, port)

    cipher_suite = CipherSuite(cipher_suite, protocol)
    cipher_suite.parse_cipher_suite()
    cipher_suite.parse_protocol_version()
    cipher_suite.rate_cipher_suite()

    certificate = Certificate(certificate, cert_verified)
    certificate.parse_certificate()
    certificate.rate_certificate()

    protocol_support = ProtocolSupport(args.url, port)
    protocol_support.scan_protocols()
    protocol_support.rate_protocols()

    versions = WebServerSoft(args.url, port, args.nmap_scan)
    versions.scan_server_software()

    # Get the version the initial connection was made on
    main_version = list(cipher_suite.parameters[PType.protocol].keys())[0]
    vulnerabilities = vulnerability_scan((args.url, port), args.test, main_version)

    logging.info('Scanning done.')
    return TextOutput.dump_to_dict((cipher_suite.parameters, cipher_suite.rating),
                                   (certificate.parameters, certificate.rating),
                                   (protocol_support.versions, protocol_support.rating),
                                   certificate.non_parameters,
                                   versions.versions, vulnerabilities,
                                   port, args.url)


if __name__ == "__main__":
    out = tls_test(sys.argv[1:])
    if out: print(out)
