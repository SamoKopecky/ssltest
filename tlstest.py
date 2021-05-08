#!/usr/bin/python3

import argparse
import sys
import logging
import json
import textwrap
import traceback
import scan_vulnerabilities.hearbleed as heartbleed
import scan_vulnerabilities.ccs_injection as ccs_injection
import scan_vulnerabilities.insec_renegotiation as rene
import scan_vulnerabilities.poodle as poodle

from scan_parameters.ratable.CipherSuite import CipherSuite
from scan_parameters.ratable.Certificate import Certificate
from scan_parameters.non_ratable.ProtocolSupport import ProtocolSupport
from scan_parameters.non_ratable.WebServerSoft import WebServerSoft
from scan_parameters.connection.connection_utils import get_website_info
from scan_parameters.non_ratable.port_discovery import discover_ports
from scan_parameters.utils import fix_url
from text_output.TextOutput import TextOutput
from scan_vulnerabilities.multitheard_scan import scan_vulnerabilities


def main():
    args = parse_options()
    if '/' in args.url:
        args.url = fix_url(args.url)
    info_report_option(args)
    nmap_discover_option(args)
    output_data = scan_all_ports(args)
    json_option(args, output_data)


def vulnerability_scan(address, tests):
    """
    Forwards the appropriate tests to multithreading function

    :param address: tuple of an url and port
    :param tests: input option for tests
    :return: dictionary of scanned results
    """
    if not tests:
        return {}
    scans = []
    switcher = {
        1: (heartbleed.scan, 'Heartbleed'),
        2: (ccs_injection.scan, 'CSS injection'),
        3: (rene.scan, 'Insecure renegotiation'),
        4: (poodle.scan, 'ZombiePOODLE/GOLDENPOOLDE')
    }
    for test in tests:
        scans.append(switcher.get(test))
    return scan_vulnerabilities(scans, address)


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
    elif args.json is None:
        print(json_output_data)
    else:
        file = open(args.json, 'w')
        file.write(json_output_data)


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
            print(f'Unexpected exception occurred: {ex}')
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
            print(f'Unexpected exception occurred: {ex}')
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


def parse_options():
    """
    Parse input options.

    :return: object of parsed arguments
    """
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
                        change output to json format, if specified requires
                        output file name as an argument
                        '''))
    parser.add_argument('-t', '--test', type=int, metavar='test_num', nargs='+',
                        help=textwrap.dedent('''\
                        test the server for a specified vulnerability
                        possible vulnerabilities (separate with spaces):
                            1: Heartbleed
                            2: ChangeCipherSpec Injection
                            3: Insecure renegotiation
                            4: ZombiePOODLE/GOLDENPOODLE
                        '''))
    parser.add_argument('-i', '--information', action='store_true', default=False, help='output some information')
    parser.add_argument('-v', '--verbose', action='store_true', default=False, help='output more information')
    args = parser.parse_args()
    check_test_numbers(args, parser)
    return args


def check_test_numbers(args, parser):
    if not args.test:
        return
    unknown_tests = list(filter(lambda test: test not in [1, 2, 3, 4], args.test))
    if unknown_tests:
        parser.print_usage()
        if len(unknown_tests) > 1:
            unknown_tests = list(map(str, unknown_tests))
            print(f'Numbers {", ".join(unknown_tests)} are not test numbers.')
        else:
            print(f'Number {unknown_tests[0]} is not a test number.')
        exit(1)


def scan(args, port: int):
    """
    Call other scanning functions for a specific url and port

    :param args: parsed arguments
    :param port: list of port to be scanned
    :return: a single dictionary containing scanned data
    """
    logging.info(f'Scanning for {args.url}:{port}')
    certificate, cipher_suite, protocol = get_website_info(args.url, port)

    cipher_suite = CipherSuite(cipher_suite, protocol)
    cipher_suite.rate()

    certificate = Certificate(certificate)
    certificate.rate()

    protocol_support = ProtocolSupport(args.url, port)
    protocol_support.rate_protocols()

    versions = WebServerSoft(args.url, port, args.nmap_scan)
    versions.scan_server_software()

    vulnerabilities = vulnerability_scan((args.url, port), args.test)

    logging.info('Scanning done.')
    return TextOutput.dump_to_dict((cipher_suite.parameters, cipher_suite.rating),
                                   (certificate.parameters, certificate.rating),
                                   (protocol_support.versions, protocol_support.rating),
                                   certificate.non_parameters,
                                   versions.versions, vulnerabilities,
                                   port, args.url)


if __name__ == "__main__":
    main()
