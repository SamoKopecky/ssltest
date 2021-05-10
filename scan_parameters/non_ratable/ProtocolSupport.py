import logging

from OpenSSL import SSL
from ..utils import rate_parameter
from ..ratable.PType import PType
from ..connection.connection_utils import create_session_pyopenssl


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
        ssl_versions = {
            SSL.TLSv1_METHOD: "TLSv1",
            SSL.TLSv1_1_METHOD: "TLSv1.1",
            SSL.TLSv1_2_METHOD: "TLSv1.2",
            SSL.SSLv23_METHOD: ""
        }
        supported_protocols = []
        unsupported_protocols = []
        for num_version in list(ssl_versions.keys()):
            context = SSL.Context(num_version)
            version = ssl_versions[num_version]
            try:
                ssl_socket = create_session_pyopenssl(self.url, self.port, context)
                if version == "":
                    version = ssl_socket.get_protocol_version_name()
                ssl_socket.close()
                if version not in supported_protocols:
                    supported_protocols.append(version)
            except SSL.Error as e:
                unsupported_protocols.append(version)
        # Need to do this since there is no explicit option for TLSv1.3
        if 'TLSv1.3' not in supported_protocols:
            unsupported_protocols.append('TLSv1.3')
        return supported_protocols, unsupported_protocols

    def rate_protocols(self):
        """
        Rate the scanned protocols.
        """
        logging.info('Scanning TLS versions...')
        supported_protocols, unsupported_protocols = self.scan_protocols()
        for protocol in supported_protocols:
            self.versions[PType.protocols][protocol] = rate_parameter(PType.protocol, protocol)
        for no_protocol in unsupported_protocols:
            self.versions[PType.no_protocol][no_protocol] = rate_parameter(PType.no_protocol, no_protocol)
        if not self.versions:
            return
        ratings = list(self.versions[PType.protocols].values()) + list(self.versions[PType.no_protocol].values())
        self.rating = max(ratings)
