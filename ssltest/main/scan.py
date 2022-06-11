import logging

from ..core.connection_utils import get_web_server_info
from ..core.WebServerSoft import WebServerSoft
from ..core.Certificate import Certificate
from ..core.CipherSuite import CipherSuite
from ..core.CipherSuites import CipherSuites
from ..core.Parameters import Parameters
from ..core.ProtocolSupport import ProtocolSupport
from ..vulnerabilities.TestRunner import TestRunner
from ..output.TextOutput import TextOutput
from .utils import Address

log = logging.getLogger(__name__)


def handle_scan_output(args, port, only_json):
    """
    Handles the output of scanning

    :param Namespace args: Parsed input arguments
    :param int port: port to scan on
    :param only_json:
    :return:
    """
    address = Address(args.url, port)
    address_str = f'{address.url}:{address.port}'
    json_data = {address_str: {}}
    handlers = []
    text_output = None
    if not only_json:
        text_output = TextOutput(address)
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

    :param Namespace args: Parsed input arguments
    :param Address address: Address of the web server
    :return: Single dictionary containing scanned data
    :rtype: dict
    """

    log.info(f'Scanning for {address.url}:{address.port}')

    protocol_support = ProtocolSupport(address, args.timeout)
    protocol_support.scan_protocols()
    protocol_support.rate_protocols()
    yield {'protocol_support': protocol_support.get_json()}

    web_server = get_web_server_info(
        address, protocol_support.supported, args.worst, args.timeout)

    cipher_suite = CipherSuite(web_server.cipher_suite, web_server.protocol)
    cipher_suite.parse_cipher_suite()
    cipher_suite.parse_protocol_version()
    cipher_suite.rate_cipher_suite()

    certificate = Certificate(web_server.certificate,
                              web_server.cert_verified, args.short_cert)
    certificate.parse_certificate()
    certificate.rate_certificate()

    yield {'parameters': Parameters.get_params_json(cipher_suite, certificate)}
    yield {'certificate_info': certificate.get_json()}

    web_server_soft = WebServerSoft(address, args.nmap_scan)
    web_server_soft.scan_server_software()
    yield {'web_server_software': web_server_soft.software}

    test_runner = TestRunner(address, args.timeout,
                             web_server.protocol, protocol_support.supported)
    yield {'vulnerabilities': test_runner.run_tests(test_option(args))}

    cipher_suites = CipherSuites(
        address, protocol_support.supported, args.timeout)
    option_result = cipher_suites_option(args, web_server.protocol)
    if option_result[0]:
        cipher_suites.scan_cipher_suites(option_result[1])
        cipher_suites.rate_cipher_suites()
    yield {'cipher_suites': cipher_suites.supported}

    log.info(f'Scanning done for {address.url}:{address.port}')


def test_option(args):
    """
    Handle test option

    :param Namespace args: Parsed input arguments
    :return: Tests to be tested
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

    :param Namespace args: Parsed input arguments
    :param str protocol: Protocol of the main connection
    :return: List of bool values, 1st -- scan at all, 2nd -- only SSLv2 scan
    :rtype: list
    """
    return_val = [False, False]
    if protocol == 'SSLv2' and not args.cipher_suites:
        return_val[1] = True
    elif args.cipher_suites:
        return_val[0] = True
    return return_val