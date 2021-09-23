import logging
import socket

from .PType import PType
from ..connections.connection_utils import create_session, create_ssl_context
from ..connections.SSLv3 import SSLv3
from ..connections.SSLv2 import SSLv2
from .Parameters import Parameters


class ProtocolSupport:

    def __init__(self, url: str, port: int, timeout):
        self.versions = {PType.protocols: {}, PType.no_protocol: {}}
        self.supported_protocols = []
        self.unsupported_protocols = []
        self.url = url
        self.port = port
        self.rating = 0
        self.timeout = timeout

    def scan_protocols(self):
        """
        Test for all possible SSL/TLS versions which the server supports

        Convert protocol versions to dict with PType to get them ready for rating
        """
        logging.info('Scanning SSL/TLS versions...')
        self.scan_ssl_protocols()
        self.scan_tls_protocols()
        for protocol in self.supported_protocols:
            self.versions[PType.protocols][protocol] = 'N/A'
        for no_protocol in self.unsupported_protocols:
            self.versions[PType.no_protocol][no_protocol] = 'N/A'

    def scan_ssl_protocols(self):
        """
        Test for all possible SSL versions which the server supports
        """
        ssl_versions = [
            SSLv2,
            SSLv3
        ]
        for ssl_version in ssl_versions:
            ssl_version = ssl_version(self.url, self.port, self.timeout)
            logging.info(f'scanning for {ssl_version.protocol}...')
            try:
                ssl_version.send_client_hello()
            except socket.error:
                pass
            result = ssl_version.scan_protocol_support()
            if result:
                self.supported_protocols.append(ssl_version.protocol)
            else:
                self.unsupported_protocols.append(ssl_version.protocol)

    def scan_tls_protocols(self):
        """
        Test for all possible TLS versions which the server supports
        """
        tls_versions = [
            'TLSv1.0',
            'TLSv1.1',
            'TLSv1.2',
            'TLSv1.3'
        ]
        for version in tls_versions:
            logging.info(f'scanning for {version}...')
            context = create_ssl_context(version)
            try:
                ssl_socket, _ = create_session(self.url, self.port, False, context, self.timeout)
                ssl_socket.close()
                self.supported_protocols.append(version)
            except socket.error:
                self.unsupported_protocols.append(version)

    def rate_protocols(self):
        """
        Rate the scanned protocols
        """
        for protocol in list(self.versions[PType.protocols].keys()):
            self.versions[PType.protocols][protocol] = Parameters.rate_parameter(PType.protocol, protocol)
        for no_protocol in list(self.versions[PType.no_protocol].keys()):
            self.versions[PType.no_protocol][no_protocol] = Parameters.rate_parameter(PType.no_protocol, no_protocol)
        if not self.versions:
            return
        ratings = list(self.versions[PType.protocols].values()) + list(self.versions[PType.no_protocol].values())
        self.rating = max(ratings)
