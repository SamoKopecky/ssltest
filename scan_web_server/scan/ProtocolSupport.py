from scan_web_server.rate.PType import PType
from ..utils import *
from ..connection.connection_utils import *


class ProtocolSupport:

    def __init__(self, hostname, port):
        self.versions = {}
        self.hostname = hostname
        self.port = port
        self.rating = 0

    def scan_protocols(self):
        """
        Test for all possible TLS versions which the server supports.

        :return: list of the supported protocols.
        """
        ssl_versions = [
            SSL.TLSv1_METHOD,
            SSL.TLSv1_1_METHOD,
            SSL.TLSv1_2_METHOD,
            SSL.SSLv23_METHOD
        ]
        supported_protocols = []
        for version in ssl_versions:
            context = SSL.Context(version)
            try:
                ssl_socket = create_session_pyopenssl(self.hostname, self.port, context)
                version = ssl_socket.get_protocol_version_name()
                ssl_socket.close()
                if version not in supported_protocols:
                    supported_protocols.append(version)
            except SSL.Error:
                continue
        return supported_protocols

    def rate_protocols(self):
        """
        Rate the scanned protocols.
        """
        print('Scanning for TLS versions...')
        supported_protocols = self.scan_protocols()
        for protocol in supported_protocols:
            self.versions[protocol] = rate_parameter(PType.protocol, protocol)
        self.rating = max(self.versions.values())

    def rate(self):
        self.rate_protocols()
        return self.rating
