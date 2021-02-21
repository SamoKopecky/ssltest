#!/usr/bin/python3
from pprint import pprint

from scan_web_server.scan.CipherSuite import CipherSuite
from scan_web_server.scan.Certificate import Certificate
from scan_web_server.scan.ProtocolSupport import ProtocolSupport
from scan_web_server.scan.webserver_version import scan_versions
from scan_web_server.connection.connection_utils import get_website_info

website = str(input("Webová adresa: ") or 'vutbr.cz')
scan_nmap = str(input("Skenovať z nmap ? (Y/N): ") or 'N')
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
