#!/usr/bin/python3
import argparse
import sys
import logging
from pprint import pprint
from scan_web_server.rate.CipherSuite import CipherSuite
from scan_web_server.rate.Certificate import Certificate
from scan_web_server.scan.ProtocolSupport import ProtocolSupport
from scan_web_server.scan.WebServerVersion import WebServerVersion
from scan_web_server.connection.connection_utils import get_website_info
from scan_web_server.scan.port_discovery import discover_ports
from scan_web_server.utils import fix_hostname
from scan_vulnerabilities.Hearbleed import test_heartbleed


def main():
    logging.basicConfig(stream=sys.stderr, level=logging.INFO)
    args = parse_options()
    if '/' in args.url:
        args.url = fix_hostname(args.url)
    if args.nmap_discover is True:
        scanned_ports = discover_ports(args.url)
        scanned_ports = list(filter(lambda scanned_port: scanned_port not in args.port, scanned_ports))
        args.port.extend(scanned_ports)
    for port in args.port:
        try:
            scan(args, port)
        except Exception as ex:
            print(f'Unexpected exception occurred: {ex}')


def parse_options():
    """
    Parse input options.

    :return: object of parsed arguments
    """
    parser = argparse.ArgumentParser(
        description='Script that scans a webservers cryptographic parameters and vulnerabilities')
    required = parser.add_argument_group('required arguments')
    required.add_argument('-u', '--url', required=True, metavar='url', help='url to scan')
    parser.add_argument('-ns', '--nmap-server', action='store_true', default=False,
                        help='use nmap to scan the server version')
    parser.add_argument('-nd', '--nmap-discover', action='store_true', default=False,
                        help='use nmap to discover web server ports')
    parser.add_argument('-p', '--port', default=[443], type=int, nargs='*', metavar='port',
                        help='port or ports(separate with spaces) to scan on (default: 443)')
    parser.add_argument('-j', '--json', action='store_true', default=False, help='change output to json format')
    parser.add_argument('-H', '--heartbleed', action='store_true', default=False,
                        help='scan for heartbleed vulnerability')
    args = parser.parse_args()
    return args


def scan(args, port):
    """
    Call other scanning functions for a specific url and port

    :param website: url to be scanned
    :param port: list of ports to be scanned
    :param scan_nmap: whether to scan with nmap or not
    :return:
    """
    print(f'---------------Scanning for port {port}---------------')  # Temporary
    final_rating = []
    certificate, cipher_suite, protocol = get_website_info(args.url, port)

    cipher_suite_parameters = CipherSuite(cipher_suite, protocol)
    final_rating.append(cipher_suite_parameters.rate())

    certificate_parameters = Certificate(certificate)
    final_rating.append(certificate_parameters.rate())

    protocol_support = ProtocolSupport(args.url, port)
    final_rating.append(protocol_support.rate())

    versions = WebServerVersion(args.url, port, args.nmap_server)
    versions.scan_versions()

    print_scan(certificate_parameters, cipher_suite_parameters, final_rating, protocol_support, versions)
    if args.heartbleed is True:
        print(test_heartbleed(args.url, port))


def print_scan(certificate_parameters, cipher_suite_parameters, final_rating, protocol_support, versions):
    """
    Temporary function for printing output
    """
    pprint(cipher_suite_parameters.parameters)
    pprint(certificate_parameters.parameters)
    pprint(protocol_support.versions)
    pprint(versions.versions)
    print(f'rating: {max(final_rating)}')


if __name__ == "__main__":
    main()
