import logging

from ..network.Endpoint import Endpoint
from ..output.TextOutput import TextOutput
from ..parameters.ratable.Certificate import Certificate
from ..parameters.ratable.CipherSuite import CipherSuite
from ..parameters.ratable.CipherSuites import CipherSuites
from ..parameters.ratable.Parameters import Parameters
from ..parameters.ratable.ProtocolSupport import ProtocolSupport
from ..parameters.unratable.WebServerSoft import WebServerSoft
from ..sockets.SocketAddress import SocketAddress
from ..vulnerabilities.TestRunner import TestRunner

log = logging.getLogger(__name__)


def handle_scan_output(args, port, only_json):
    """
    Handle output of scanning, depending on arguments

    :param argparse.Namespace args: Parsed script arguments
    :param int port: Port to scan on
    :param bool only_json: Not text output for the script
    :return: Json scan data
    :rtype: dict
    """
    address = SocketAddress(args.url, port)
    address_str = f"{address.url}:{address.port}"
    json_data = {address_str: {}}
    handlers = []
    text_output = None
    if not only_json:
        text_output = TextOutput(address, args)
        text_output.print_address()
        handlers.append(text_output.print_category)
    handlers.append(json_data[address_str].update)
    for json_output in scan(args, address):
        [handler(json_output) for handler in handlers]
    if text_output is not None:
        del text_output
    return json_data


def scan(args, address):
    """
    Call scanning/testing functions for a specific url and port

    :param argparse.Namespace args: Parsed script arguments
    :param SocketAddress address: Address of the web server
    :return: Single dictionary containing scanned data
    :rtype: dict
    """

    log.info(f"Scanning for {address.url}:{address.port}")

    protocol_support = ProtocolSupport(address)
    protocol_support.scan_protocols()
    protocol_support.rate_protocols()
    yield {"protocol_support": protocol_support.get_json()}

    endpoint = Endpoint(address, protocol_support.supported, args)
    endpoint.scan_endpoint()

    cipher_suite = CipherSuite(endpoint.cipher_suite, endpoint.protocol)
    cipher_suite.parse_cipher_suite()
    cipher_suite.parse_protocol_version()
    cipher_suite.rate_cipher_suite()

    certificate = Certificate(endpoint.certificates, endpoint.cert_verified, args)
    certificate.parse_certificates()
    certificate.rate_certificates()

    yield {"parameters": Parameters.get_params_json(cipher_suite, certificate)}
    yield {"certificate_info": certificate.get_json()}

    web_server_soft = WebServerSoft(address, args.nmap_scan)
    web_server_soft.scan_server_software()
    yield {"web_server_software": web_server_soft.software}

    test_runner = TestRunner(address, endpoint.protocol, protocol_support.supported)
    yield {"vulnerabilities": test_runner.run_tests(test_option(args))}

    cipher_suites = CipherSuites(address, protocol_support.supported)
    option_result = cipher_suites_option(args, endpoint.protocol)
    if option_result[0]:
        cipher_suites.scan_cipher_suites(option_result[1])
        cipher_suites.rate_cipher_suites()
    yield {"cipher_suites": cipher_suites.supported}

    log.info(f"Scanning done for {address.url}:{address.port}")


def test_option(args):
    """
    Filter tests based on arguments

    :param argparse.Namespace args: Parsed script arguments
    :return: Filtered tests
    :rtype: list
    """
    tests_switcher = TestRunner.get_tests_switcher()
    # if no -t argument is present test all vulnerabilities
    if not args.test:
        # Remove test at 0th index
        tests = list(tests_switcher.values())[1:]
    elif 0 in args.test:
        return []
    else:
        tests = list(map(lambda t: tests_switcher[t], args.test))
    return tests


def cipher_suites_option(args, protocol):
    """
    Handle cipher suite support scanning option

    :param argparse.Namespace args: Parsed script arguments
    :param str protocol: Protocol of the main connection
    :return: List of bool values, 1st -- scan at all, 2nd -- only SSLv2 scan
    :rtype: list[bool, bool]
    """
    return_val = [False, False]
    if protocol == "SSLv2" and not args.cipher_suites:
        return_val[1] = True
    elif args.cipher_suites:
        return_val[0] = True
    return return_val
