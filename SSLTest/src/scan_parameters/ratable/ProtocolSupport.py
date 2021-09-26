import logging
import socket

from .PType import PType
from ..connections.connection_utils import create_session, create_ssl_context
from ..connections.SSLv3 import SSLv3
from ..connections.SSLv2 import SSLv2
from .Parameters import Parameters


class ProtocolSupport:

    def __init__(self, address, timeout):
        self.protocols = {PType.protocols: {}, PType.no_protocol: {}}
        self.supported = []
        self.unsupported = []
        self.address = address
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
        for protocol in self.supported:
            self.protocols[PType.protocols][protocol] = 'N/A'
        for no_protocol in self.unsupported:
            self.protocols[PType.no_protocol][no_protocol] = 'N/A'

    def scan_ssl_protocols(self):
        """
        Test for all possible SSL versions which the server supports
        """
        ssl_versions = [
            SSLv2,
            SSLv3
        ]
        for ssl_version in ssl_versions:
            ssl_version = ssl_version(self.address, self.timeout)
            logging.info(f'scanning for {ssl_version.protocol}...')
            try:
                ssl_version.send_client_hello()
            except socket.error:
                pass
            result = ssl_version.scan_protocol_support()
            if result:
                self.supported.append(ssl_version.protocol)
            else:
                self.unsupported.append(ssl_version.protocol)

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
                ssl_socket, _ = create_session(self.address, False, context, self.timeout)
                ssl_socket.close()
                self.supported.append(version)
            except socket.error:
                self.unsupported.append(version)

    def rate_protocols(self):
        """
        Rate the scanned protocols
        """
        for protocol in list(self.protocols[PType.protocols].keys()):
            self.protocols[PType.protocols][protocol] = Parameters.rate_parameter(PType.protocol, protocol)
        for no_protocol in list(self.protocols[PType.no_protocol].keys()):
            self.protocols[PType.no_protocol][no_protocol] = Parameters.rate_parameter(PType.no_protocol, no_protocol)
        if not self.protocols:
            return
        ratings = list(self.protocols[PType.protocols].values()) + list(self.protocols[PType.no_protocol].values())
        self.rating = max(ratings)
