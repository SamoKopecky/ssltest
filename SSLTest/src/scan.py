import concurrent.futures as cf
import logging

from .scan_parameters.connections.connection_utils import get_webserver_info
from .scan_parameters.non_ratable.WebServerSoft import WebServerSoft
from .scan_parameters.ratable.Certificate import Certificate
from .scan_parameters.ratable.CipherSuite import CipherSuite
from .scan_parameters.ratable.CipherSuites import CipherSuites
from .scan_parameters.ratable.PType import PType
from .scan_parameters.ratable.ProtocolSupport import ProtocolSupport
from .scan_vulnerabilities.tests.CCSInjection import CCSInjection
from .scan_vulnerabilities.tests.Crime import Crime
from .scan_vulnerabilities.tests.Drown import Drown
from .scan_vulnerabilities.tests.FallbackSCSVSupport import FallbackSCSVSupport
from .scan_vulnerabilities.tests.ForwardSecrecySupport import ForwardSecrecySupport
from .scan_vulnerabilities.tests.Heartbleed import Heartbleed
from .scan_vulnerabilities.tests.InsecureRenegotiation import InsecureRenegotiation
from .scan_vulnerabilities.tests.RC4Support import RC4Support
from .scan_vulnerabilities.tests.SessionTicketSupport import SessionTicketSupport
from .scan_vulnerabilities.tests.Sweet32 import Sweet32
from .text_output.TextOutput import TextOutput
from .utils import Address

log = logging.getLogger(__name__)


# TODO:
# Add address at the top with the port to know which server is being scanned
# Add parameters yielding
# Add Category print in TextOutput (Protocol support no indent)
# Add filtering so when a category is empty nothing is displayed
# Maybe implement parsing json from an object in each class

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
    yield protocol_support.scan().rate().get_json()

    webserver = get_webserver_info(address, protocol_support.supported, args.worst, args.timeout)

    cipher_suite = CipherSuite(webserver.cipher_suite, webserver.protocol)
    cipher_suite.parse_cipher_suite()
    cipher_suite.parse_protocol_version()
    cipher_suite.rate_cipher_suite()

    certificate = Certificate(webserver.certificate, webserver.cert_verified)
    certificate.parse_certificate()
    certificate.rate_certificate()

    worst_rating = max([cipher_suite.rating, certificate.rating])
    parameters = {key.name: value for key, value in cipher_suite.parameters.items()}
    for key, value in certificate.parameters.items():
        if key == PType.cert_pub_key_algorithm and not parameters[key.name] == {'N/A': '0'}:
            continue
        parameters.update({key.name: value})
    parameters.update({'rating': worst_rating})
    yield {'parameters': parameters}
    yield {'certificate_info': {key.name: value for key, value in certificate.non_parameters.items()}}

    web_server_soft = WebServerSoft(address, args.nmap_scan)
    web_server_soft.scan_server_software()
    yield {'web_server_software': web_server_soft.software}

    cipher_suites = cipher_suites_option(address, args, protocol_support.supported, webserver.protocol)
    yield {'cipher_suites': cipher_suites.supported}

    vulnerabilities = test_option(args, address, protocol_support.supported, webserver.protocol)
    yield {'vulnerabilities': vulnerabilities}

    log.info(f'Scanning done for {address.url}:{address.port}')


def handle_scan_output(args, port, only_json):
    """
    TODO:
    :param args:
    :param port:
    :param only_json:
    :return:
    """
    address = Address(args.url, port)
    address_str = f"{address.url}:{address.port}"
    json_data = {address_str: {}}
    handlers = []
    if not only_json:
        text_output = TextOutput(address)
        text_output.print_address()
        handlers.append(text_output.print_data)
    handlers.append(json_data[address_str].update)
    for json_output in scan(args, address):
        [handler(json_output) for handler in handlers]
    return json_data


# Vulnerability Tests
# -------------------

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
        3: (Drown, Drown.test_name),
        4: (FallbackSCSVSupport, FallbackSCSVSupport.test_name),
        5: (ForwardSecrecySupport, ForwardSecrecySupport.test_name),
        6: (Heartbleed, Heartbleed.test_name),
        7: (InsecureRenegotiation, InsecureRenegotiation.test_name),
        8: (RC4Support, RC4Support.test_name),
        9: (SessionTicketSupport, SessionTicketSupport.test_name),
        10: (Sweet32, Sweet32.test_name)
    }


def test_option(args, address, supported_protocols, protocol):
    """
    Forward the appropriate tests to multithreading function

    :param Namespace args: Input arguments
    :param Address address: Webserver address
    :param supported_protocols: Supported SSL/TLS protocols by the server
    :param str protocol: SSL/TLS protocol to scan on
    :return: Test results
    :rtype: dict
    """
    tests_switcher = get_tests_switcher()
    # if no -t argument is present
    if not args.test:
        # Remove test at 0th index
        classes = list(tests_switcher.values())[1:]
    elif 0 in args.test:
        return {}
    else:
        classes = list(map(lambda t: tests_switcher[t], args.test))
    return vulnerability_scans(classes, address, supported_protocols, args.timeout, protocol)


def vulnerability_scans(classes, address, supported_protocols, timeout, protocol):
    """
    Run chosen vulnerability tests in parallel

    :param list classes: Classes to be run
    :param tuple address: Url and port
    :param list supported_protocols: List of supported protocols
    :param int timeout: Timeout in seconds
    :param str protocol: SSL/TLS protocol
    :return: Tests results
    :rtype: dict
    """
    # Output dictionary
    output = {}
    # Dictionary that all the threads live in where the key
    # is the thread (future) and value is the function name
    futures = {}
    log.info(f"Creating {len(classes)} threads for vulnerability tests")
    with cf.ThreadPoolExecutor(max_workers=len(classes)) as executor:
        for test_class in classes:
            # 0th index is the function, 1st index is the function name
            scan_class = test_class[0](supported_protocols, address, timeout, protocol)
            execution = executor.submit(scan_class.scan)
            futures.update({execution: test_class[1]})
        for execution in cf.as_completed(futures):
            function_name = futures[execution]
            data = execution.result()
            output.update({function_name: data})
    return output


# Cipher suites scanning
# ----------------------

def cipher_suites_option(address, args, supported_protocols, protocol):
    """
    Handle cipher suite support scanning

    :param Address address: Webserver address
    :param Namespace args: Parsed input arguments
    :param list supported_protocols: Supported SSL/TLS protocols
    :param str protocol: Protocol of the main connection
    :return: Dictionary of supported protocols
    :rtype: CipherSuites
    """
    cipher_suites = CipherSuites(address, supported_protocols, args.timeout)
    if protocol == 'SSLv2' and not args.cipher_suites:
        cipher_suites.scan_sslv2_cipher_suites()
    elif args.cipher_suites:
        cipher_suites.scan_cipher_suites()
    cipher_suites.rate_cipher_suites()
    return cipher_suites
