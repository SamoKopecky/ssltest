#!/usr/bin/python3
import argparse
import sys
import logging
import json
import textwrap
import traceback
from scan_web_server.rate.CipherSuite import CipherSuite
from scan_web_server.rate.Certificate import Certificate
from scan_web_server.scan.ProtocolSupport import ProtocolSupport
from scan_web_server.scan.WebServerVersion import WebServerVersion
from scan_web_server.connection.connection_utils import get_website_info
from scan_web_server.scan.port_discovery import discover_ports
from scan_web_server.utils import fix_url
from text_output.TextOutput import TextOutput
import scan_vulnerabilities.hearbleed as heartbleed
import scan_vulnerabilities.ccs_injection as ccs_injection
import scan_vulnerabilities.insec_renegotiation as rene
import scan_vulnerabilities.poodle as poodle


def main():
    args = parse_options()
    if '/' in args.url:
        args.url = fix_url(args.url)
    verbose_option(args)
    nmap_discover_option(args)
    output_data = scan_all_ports(args)
    output_handler(args, output_data)


def vulnerability_scan(address, tests):
    """
    Call tests given in input options

    :param address: tuple of an url and port
    :param tests: input option for tests
    :return: dictionary of scanned results
    """
    scans = []
    results = {}
    switcher = {
        1: (heartbleed.scan, 'Heartbleed'),
        2: (ccs_injection.scan, 'CSS injection'),
        3: (rene.scan, 'insecure renegotiation'),
        4: (poodle.scan, 'ZombiePOODLE/GOLDENPOOLDE')
    }
    for test in tests:
        scans.append(switcher.get(test))
    for scan_method in scans:
        results.update({scan_method[1]: scan_method[0](address)})
    return results


def output_handler(args, output_data):
    """
    Handle output depending on the input options

    :param args: input options
    :param output_data: json data to output
    """
    json_output_data = json.dumps(output_data, indent=2)
    if args.json is not None:
        file = open('output.json', 'w')
        file.write(json_output_data)
    else:
        text_output = TextOutput(json_output_data)
        text_output.text_output()


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
            tb = traceback.extract_stack()
            logging.debug(''.join(traceback.format_list(tb)[:-1]))
            logging.debug(ex)
            print(f'Unexpected exception occurred: {ex}')
    return output_data


def nmap_discover_option(args):
    """
    Discover usable ports

    :param args: input options
    """
    if args.nmap_discover:
        scanned_ports = discover_ports(args.url)
        scanned_ports = list(filter(lambda port: port not in args.port, scanned_ports))
        args.port.extend(scanned_ports)


def verbose_option(args):
    """
    Handle verbose option

    :param args: input options
    """
    if args.verbose:
        logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    else:
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
    parser.add_argument('-ns', '--nmap-server', action='store_true', default=False,
                        help='use nmap to scan the server version')
    parser.add_argument('-nd', '--nmap-discover', action='store_true', default=False,
                        help='use nmap to discover web server ports')
    parser.add_argument('-p', '--port', default=[443], type=int, nargs='+', metavar='port',
                        help='port or ports (separate with spaces) to scan on (default: %(default)s)')
    parser.add_argument('-j', '--json', action='store', metavar='output_file', required=False,
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
    parser.add_argument('-v', '--verbose', action='store_true', default=False, help='output more information')
    args = parser.parse_args()
    return args


def scan(args, port: int):
    """
    Call other scanning functions for a specific url and port

    :param args: parsed arguments
    :param port: list of port to be scanned
    :return: a single dictionary containing scanned data
    """
    print(f'----------------Scanning for {args.url}:{port}---------------------')
    certificate, cipher_suite, protocol = get_website_info(args.url, port)

    cipher_suite = CipherSuite(cipher_suite, protocol)
    cipher_suite.rate()

    certificate = Certificate(certificate)
    certificate.rate()

    protocol_support = ProtocolSupport(args.url, port)
    protocol_support.rate_protocols()

    versions = WebServerVersion(args.url, port, args.nmap_server)
    versions.scan_versions()

    vulnerabilities = vulnerability_scan((args.url, port), args.test)

    print('Done.')
    return TextOutput.dump_to_dict((cipher_suite.parameters, cipher_suite.rating),
                                   (certificate.parameters, certificate.rating),
                                   (protocol_support.versions, protocol_support.rating),
                                   certificate.non_parameters,
                                   versions.versions, vulnerabilities,
                                   port, args.url)


if __name__ == "__main__":
    main()
