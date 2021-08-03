import logging

from OpenSSL import SSL
from ..utils import rate_parameter
from ..ratable.PType import PType
from ..connection.connection_utils import create_session_pyopenssl
from ssl_scan.SSLv3 import SSLv3


class ProtocolSupport:

    def __init__(self, url: str, port: int):
        self.versions = {PType.protocols: {}, PType.no_protocol: {}}
        self.url = url
        self.port = port
        self.rating = 0

    def scan_protocols(self):
        """
        Test for all possible TLS versions which the server supports.

        :return: list of the supported protocols.
        """
        logging.info('Scanning TLS versions...')
        ssl_versions = {
            SSL.TLSv1_METHOD: 'TLSv1.0',
            SSL.TLSv1_1_METHOD: 'TLSv1.1',
            SSL.TLSv1_2_METHOD: 'TLSv1.2',
            SSL.SSLv23_METHOD: 'unknown'
        }
        supported_protocols = []
        unsupported_protocols = []
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
                if version not in supported_protocols:
                    supported_protocols.append(version)
            except SSL.Error as e:
                if version == 'unknown':
                    continue
                unsupported_protocols.append(version)
        # Need to do this since there is no explicit option for TLSv1.3
        if 'TLSv1.3' not in supported_protocols:
            unsupported_protocols.append('TLSv1.3')
        # SSLv3 scanning
        sslv3 = SSLv3(self.url, self.port)
        result = sslv3.scan_sslv3_version()
        if result:
            supported_protocols.append("SSLv3")
        else:
            unsupported_protocols.append("SSLv3")
        for protocol in supported_protocols:
            self.versions[PType.protocols][protocol] = 'N/A'
        for no_protocol in unsupported_protocols:
            self.versions[PType.no_protocol][no_protocol] = 'N/A'

    def rate_protocols(self):
        """
        Rate the scanned protocols.
        """
        for protocol in list(self.versions[PType.protocols].keys()):
            self.versions[PType.protocols][protocol] = rate_parameter(PType.protocol, protocol)
        for no_protocol in list(self.versions[PType.no_protocol].keys()):
            self.versions[PType.no_protocol][no_protocol] = rate_parameter(PType.no_protocol, no_protocol)
        if not self.versions:
            return
        ratings = list(self.versions[PType.protocols].values()) + list(self.versions[PType.no_protocol].values())
        self.rating = max(ratings)
