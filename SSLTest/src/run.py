import json
import logging
import sys
import traceback
import concurrent.futures as cf

from .utils import bytes_to_cipher_suite

from .scan_parameters.connections.connection_utils import get_website_info
from .scan_parameters.ratable.ProtocolSupport import ProtocolSupport
from .scan_parameters.non_ratable.WebServerSoft import WebServerSoft
from .scan_parameters.non_ratable.port_discovery import discover_ports
from .scan_parameters.ratable.Certificate import Certificate
from .scan_parameters.ratable.CipherSuite import CipherSuite
from .scan_parameters.ratable.CipherSuites import CipherSuites
from .scan_parameters.utils import fix_url
from .scan_vulnerabilities.tests.CCSInjection import CCSInjection
from .scan_vulnerabilities.tests.Crime import Crime
from .scan_vulnerabilities.tests.Heartbleed import Heartbleed
from .scan_vulnerabilities.tests.InsecureRenegotiation import InsecureRenegotiation
from .scan_vulnerabilities.tests.RC4Support import RC4Support
from .scan_vulnerabilities.tests.SessionTicketSupport import SessionTicketSupport
from .scan_vulnerabilities.tests.FallbackSCSVSupport import FallbackSCSVSupport
from .scan_vulnerabilities.tests.Drown import Drown
from .text_output.TextOutput import TextOutput


def cipher_suites_option(args, port, supported_protocols):
    """
    Handle cipher suite support scanning

    :param args: Parsed input arguments
    :param port: Port to scan on
    :param supported_protocols: Supported SSL/TLS protocols
    :return: Dictionary of supported protocols
    :rtype: dict
    """
    if args.cipher_suites:
        cipher_suites = CipherSuites((args.url, port), supported_protocols)
        cipher_suites.scan_cipher_suites()
        return cipher_suites.supported_ciphers
    return {}


def get_tests_switcher():
    """
    Provides all the available tests switcher

    :return: All available tests
    :rtype: dict
    """
    return {
        0: (None, 'No test'),
        1: (CCSInjection, CCSInjection.test_name),
        2: (Crime, Crime.test_name),
        3: (FallbackSCSVSupport, FallbackSCSVSupport.test_name),
        4: (Heartbleed, Heartbleed.test_name),
        5: (InsecureRenegotiation, InsecureRenegotiation.test_name),
        6: (RC4Support, RC4Support.test_name),
        7: (SessionTicketSupport, SessionTicketSupport.test_name),
        8: (Drown, Drown.test_name)
    }


def test_option(address, tests, supported_protocols):
    """
    Forward the appropriate tests to multithreading function

    :param tuple address: Url and port
    :param list tests: Test numbers
    :param supported_protocols: Supported SSL/TLS protocols by the server
    :return: Test results
    :rtype: dict
    """
    tests_switcher = get_tests_switcher()
    # if no -t argument is present
    if not tests:
        # Remove test at 0th index
        scans = list(tests_switcher.values())[1:]
    elif 0 in tests:
        return {}
    else:
        scans = list(map(lambda t: tests_switcher[t], tests))
    return vulnerability_scans(scans, address, supported_protocols)


def vulnerability_scans(functions, address, supported_protocols):
    """
    Run chosen vulnerability tests in parallel

    :param list functions: Functions to be run
    :param tuple address: Url and port
    :param list supported_protocols: List of supported protocols
    :return: Tests results
    :rtype: dict
    """
    # Output dictionary
    output = {}
    # Dictionary that all the threads live in where the key
    # is the thread (future) and value is the function name
    futures = {}
    with cf.ThreadPoolExecutor(max_workers=len(functions)) as executor:
        for function in functions:
            # 0th index is the function, 1st index is the function name
            scan_class = function[0](supported_protocols, address)
            execution = executor.submit(scan_class.scan)
            futures.update({execution: function[1]})
        for execution in cf.as_completed(futures):
            function_name = futures[execution]
            data = execution.result()
            output.update({function_name: data})
    return output


def output_option(args, output_data):
    """
    Handle output depending on the input options

    :param Namespace args: Parsed input arguments
    :param dict output_data: Collected data from scanning/testing
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

    :param Namespace args: Parsed input arguments
    :return: Scanned data
    :rtype: dict
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
    Handle discover ports option

    :param Namespace args: Parsed input arguments
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
    Handle the debug and information options

    :param Namespace args: Parsed input arguments
    """
    if args.debug:
        logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    elif args.info:
        logging.basicConfig(stream=sys.stderr, level=logging.INFO)


def dump_to_dict(cipher_suite, certificate_parameters, protocol_support,
                 certificate_non_parameters, software, cipher_suites, vulnerabilities, port, url):
    """
    Dump web server parameters to a single dictionary

    :param tuple cipher_suite: Rated cipher suite parameters and the worst rating
    :param tuple certificate_parameters: Rated certificate parameters and the worst rating
    :param tuple protocol_support: Supported SSL/TLS protocols
    :param dict certificate_non_parameters: Not ratable certificate parameters such as subject/issuer
    :param dict software: Web server software which hosts the website
    :param dict cipher_suites: All scanned cipher suites
    :param dict vulnerabilities: Results from vulnerability tests
    :param int port: Scanned port
    :param str url: Scanned url
    :return: A single dictionary created from the parameters
    :rtype: dict
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
    dump.update({'cipher_suites': cipher_suites})
    dump.update({'vulnerabilities': vulnerabilities})
    return {f'{url}:{port}': dump}


def scan(args, port):
    """
    Call scanning/testing functions for a specific url and port

    :param Namespace args: Parsed input arguments
    :param int port: Port to be scanned
    :return: Single dictionary containing scanned data
    :rtype: dict
    """
    logging.info(f'Scanning for {args.url}:{port}')

    protocol_support = ProtocolSupport(args.url, port)
    protocol_support.scan_protocols()
    protocol_support.rate_protocols()

    certificate, cert_verified, cipher_suite, protocol = get_website_info(
        args.url, port, protocol_support.supported_protocols, args.worst
    )

    cipher_suite = CipherSuite(cipher_suite, protocol)
    cipher_suite.parse_cipher_suite()
    cipher_suite.parse_protocol_version()
    cipher_suite.rate_cipher_suite()

    certificate = Certificate(certificate, cert_verified)
    certificate.parse_certificate()
    certificate.rate_certificate()

    versions = WebServerSoft(args.url, port, args.nmap_scan)
    versions.scan_server_software()

    cipher_suites = cipher_suites_option(args, port, protocol_support.supported_protocols)

    vulnerabilities = test_option((args.url, port), args.test, protocol_support.supported_protocols)

    logging.info('Scanning done.')
    return dump_to_dict((cipher_suite.parameters, cipher_suite.rating),
                        (certificate.parameters, certificate.rating),
                        (protocol_support.versions, protocol_support.rating),
                        certificate.non_parameters, versions.versions, cipher_suites,
                        vulnerabilities, port, args.url)


def run(args):
    """
    Call other functions to run the script

    :param Namespace args: Parsed input arguments
    """
    if '/' in args.url:
        args.url = fix_url(args.url)
    info_report_option(args)
    nmap_discover_option(args)
    output_data = scan_all_ports(args)
    out = output_option(args, output_data)
    if out: print(out)
