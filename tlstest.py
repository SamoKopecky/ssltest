#!/usr/bin/python3
import argparse
from pprint import pprint

from scan_web_server.scan.CipherSuite import CipherSuite
from scan_web_server.scan.Certificate import Certificate
from scan_web_server.scan.ProtocolSupport import ProtocolSupport
from scan_web_server.scan.webserver_version import scan_versions
from scan_web_server.connection.connection_utils import get_website_info


def main():
    parser = argparse.ArgumentParser(
        description='Script that scans a webservers cryptographic parameters and vulnerabilities')
    required = parser.add_argument_group('required arguments')
    port_scanning = parser.add_mutually_exclusive_group()
    required.add_argument('-u', '--url', required=True, metavar='url', help='url to scan')
    parser.add_argument('-nv', '--nmap-version', action='store_true', default=False,
                        help='use nmap to scan the server version')
    port_scanning.add_argument('-np', '--nmap-port', action='store_true', default=False,
                               help='use nmap to scan for a web server port')
    port_scanning.add_argument('-p', '--port', default=443, type=int, metavar='port',
                               help='port to scan on (default: 443)')
    parser.add_argument('-j', '--json', action='store_true', default=False, help='change output to json format')
    args = parser.parse_args()
    scan(args.url, args.nmap_version)


def scan(website, scan_nmap):
    certificate, cipher_suite, protocol = get_website_info(website)

    cipher_suite_parameters = CipherSuite(cipher_suite, protocol)
    cipher_suite_parameters.rate()

    certificate_parameters = Certificate(certificate)
    certificate_parameters.rate()

    protocol_support = ProtocolSupport(website)
    protocol_support.rate()

    versions = scan_versions(website, scan_nmap)

    # temporary output
    pprint(cipher_suite_parameters.parameters)
    pprint(certificate_parameters.parameters)
    pprint(protocol_support.versions)
    pprint(versions)


if __name__ == "__main__":
    main()
