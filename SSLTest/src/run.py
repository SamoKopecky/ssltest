import json
import logging
import os
import sys
import traceback

from .fix_openssl_config import fix_openssl_config
from .scan_parameters.connections.connection_utils import get_website_info
from .scan_parameters.ratable.ProtocolSupport import ProtocolSupport
from .scan_parameters.non_ratable.WebServerSoft import WebServerSoft
from .scan_parameters.non_ratable.port_discovery import discover_ports
from .scan_parameters.ratable.Certificate import Certificate
from .scan_parameters.ratable.CipherSuite import CipherSuite
from .scan_parameters.ratable.PType import PType
from .scan_parameters.utils import fix_url
from .scan_vulnerabilities.multitheard_scan import scan_vulnerabilities
from .scan_vulnerabilities.tests import ccs_injection
from .scan_vulnerabilities.tests import crime
from .scan_vulnerabilities.tests import heartbleed
from .scan_vulnerabilities.tests import insec_renegotiation as rene
from .scan_vulnerabilities.tests import poodle
from .scan_vulnerabilities.tests import rc4_support
from .scan_vulnerabilities.tests import session_ticket
from .text_output.TextOutput import TextOutput


def get_tests_switcher():
    return {
        0: (None, 'No test'),
        1: (heartbleed.scan, 'Heartbleed'),
        2: (ccs_injection.scan, 'CCS injection'),
        3: (rene.scan, 'Insecure renegotiation'),
        4: (poodle.scan, 'ZombiePOODLE/GOLDENDOOLDE'),
        5: (session_ticket.scan, 'Session ticket support'),
        6: (crime.scan, 'CRIME'),
        7: (rc4_support.scan, 'RC4 support')
    }


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
    tests_switcher = get_tests_switcher()
    # if no -t argument is present
    if not tests:
        # Remove test at 0th index
        scans = [value for value in list(tests_switcher.values())[1:]]
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
        text_output.get_formatted_text()
        return text_output.output
    elif args.json is None:
        return json_output_data
    else:
        file = open(args.json, 'w')
        file.write(json_output_data)
        file.close()
        print(f"Output writen to {args.json}", file=sys.stderr)


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
    if args.debug:
        logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    elif args.info:
        logging.basicConfig(stream=sys.stderr, level=logging.INFO)


def dump_to_dict(cipher_suite, certificate_parameters, protocol_support,
                 certificate_non_parameters, software, vulnerabilities, port, url):
    """
    Dump web server parameters to a single dict.

    :param cipher_suite: tuple containing parameters and the worst rating
    :param certificate_parameters: tuple containing parameters and the worst rating
    :param certificate_non_parameters: certificate parameters such as subject/issuer
    :param protocol_support: dictionary of supported tls protocols
    :param software: web server software
    :param port: scanned port
    :param url: scanned url
    :param vulnerabilities: scanned vulnerabilities
    :return: dictionary
    """
    dump = {}

    # Parameters
    worst_rating = max([cipher_suite[1], certificate_parameters[1]])
    parameters = {key.name: value for key, value in cipher_suite[0].items()}
    parameters.update({key.name: value for key, value in certificate_parameters[0].items()})
    parameters.update({'rating': worst_rating})

    # Non ratable cert info
    certificate_info = {key.name: value for key, value in certificate_non_parameters.items()}

    # Protocol support
    protocols = {}
    keys = {key.name: value for key, value in protocol_support[0].items()}
    for key, value in list(keys.items()):
        protocols[key] = value
    protocols.update({'rating': protocol_support[1]})

    dump.update({'parameters': parameters})
    dump.update({'certificate_info': certificate_info})
    dump.update({'protocol_support': protocols})
    dump.update({'web_server_software': software})
    dump.update({'vulnerabilities': vulnerabilities})
    return {f'{url}:{port}': dump}


def scan(args, port: int):
    """
    Call other scanning functions for a specific url and port

    :param args: parsed arguments
    :param port: list of port to be scanned
    :return: a single dictionary containing scanned data
    """
    logging.info(f'Scanning for {args.url}:{port}')

    protocol_support = ProtocolSupport(args.url, port)
    protocol_support.scan_protocols()
    protocol_support.rate_protocols()

    certificate, cert_verified, cipher_suite, protocol = get_website_info(args.url, port,
                                                                          protocol_support.supported_protocols)

    cipher_suite = CipherSuite(cipher_suite, protocol)
    cipher_suite.parse_cipher_suite()
    cipher_suite.parse_protocol_version()
    cipher_suite.rate_cipher_suite()

    certificate = Certificate(certificate, cert_verified)
    certificate.parse_certificate()
    certificate.rate_certificate()

    versions = WebServerSoft(args.url, port, args.nmap_scan)
    versions.scan_server_software()

    # Get the version the initial connection was made on
    main_version = list(cipher_suite.parameters[PType.protocol].keys())[0]
    vulnerabilities = vulnerability_scan((args.url, port), args.test, main_version)

    logging.info('Scanning done.')
    return dump_to_dict((cipher_suite.parameters, cipher_suite.rating),
                        (certificate.parameters, certificate.rating),
                        (protocol_support.versions, protocol_support.rating),
                        certificate.non_parameters, versions.versions, vulnerabilities,
                        port, args.url)


def run(args):
    fix_conf_option(args)
    if '/' in args.url:
        args.url = fix_url(args.url)
    info_report_option(args)
    nmap_discover_option(args)
    output_data = scan_all_ports(args)
    out = json_option(args, output_data)
    if out: print(out)
