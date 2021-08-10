import logging

from OpenSSL import SSL

from .PType import PType
from ..connections.connection_utils import create_session_pyopenssl
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
            SSL.TLSv1_METHOD: 'TLSv1.0',
            SSL.TLSv1_1_METHOD: 'TLSv1.1',
            SSL.TLSv1_2_METHOD: 'TLSv1.2',
            SSL.SSLv23_METHOD: 'unknown'
        }
        for num_version in list(ssl_versions.keys()):
            context = SSL.Context(num_version)
            version = ssl_versions[num_version]
            try:
                ssl_socket = create_session_pyopenssl(self.url, self.port, context)
                if version == 'unknown':
                    version = ssl_socket.get_protocol_version_name()
                    if version == 'TLSv1':
                        version += '.0'
                ssl_socket.close()
                if version not in self.supported_protocols:
                    self.supported_protocols.append(version)
            except SSL.Error as e:
                if version == 'unknown':
                    continue
                self.unsupported_protocols.append(version)
        # Need to do this since there is no explicit option for TLSv1.3
        if 'TLSv1.3' not in self.supported_protocols:
            self.unsupported_protocols.append('TLSv1.3')

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
