import logging
import ssl
import socket

from .PType import PType
from ..connections.connection_utils import create_session
from ..utils import rate_parameter
from ..connections.SSLv3 import SSLv3
from ..connections.SSLv2 import SSLv2


class ProtocolSupport:

    def __init__(self, url: str, port: int):
        self.versions = {PType.protocols: {}, PType.no_protocol: {}}
        self.supported_protocols = []
        self.unsupported_protocols = []
        self.url = url
        self.port = port
        self.rating = 0

    def scan_protocols(self):
        """
        Test for all possible SSL/TLS versions which the server supports

        Convert protocol versions to dict with PType to get them ready for rating
        """
        logging.info('Scanning SSL/TLS versions...')
        self.scan_tls_protocols()
        self.scan_ssl_protocols()
        for protocol in self.supported_protocols:
            self.versions[PType.protocols][protocol] = 'N/A'
        for no_protocol in self.unsupported_protocols:
            self.versions[PType.no_protocol][no_protocol] = 'N/A'

    def scan_ssl_protocols(self):
        """
        Test for all possible SSL versions which the server supports
        """
        ssl_versions = [
            SSLv3(self.url, self.port),
            SSLv2(self.url, self.port)
        ]
        for ssl_version in ssl_versions:
            logging.debug(f'scanning for {ssl_version.protocol}...')
            ssl_version.send_client_hello()
            result = ssl_version.scan_version_support()
            if result:
                self.supported_protocols.append(ssl_version.protocol)
            else:
                self.unsupported_protocols.append(ssl_version.protocol)

    def scan_tls_protocols(self):
        """
        Test for all possible TLS versions which the server supports
        """
        ssl_versions = {
            ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_3: 'TLSv1.0',
            ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_3: 'TLSv1.1',
            ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_3: 'TLSv1.2',
            ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1: 'TLSv1.3'
        }
        for version, str_version in ssl_versions.items():
            logging.debug(f'scanning for {str_version}...')
            context = ssl.SSLContext()
            context.options = ssl.OP_ALL
            context.options |= version
            try:
                ssl_socket, _ = create_session(self.url, self.port, False, context)
                ssl_socket.close()
                self.supported_protocols.append(str_version)
            except socket.error:
                self.unsupported_protocols.append(str_version)

    def rate_protocols(self):
        """
        Rate the scanned protocols
        """
        for protocol in list(self.versions[PType.protocols].keys()):
            self.versions[PType.protocols][protocol] = rate_parameter(PType.protocol, protocol)
        for no_protocol in list(self.versions[PType.no_protocol].keys()):
            self.versions[PType.no_protocol][no_protocol] = rate_parameter(PType.no_protocol, no_protocol)
        if not self.versions:
            return
        ratings = list(self.versions[PType.protocols].values()) + list(self.versions[PType.no_protocol].values())
        self.rating = max(ratings)
