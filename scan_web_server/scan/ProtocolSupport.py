from OpenSSL import SSL
from ..utils import rate_parameter
from ..rate.PType import PType
from ..connection.connection_utils import create_session_pyopenssl


class ProtocolSupport:

    def __init__(self, url: str, port: int):
        self.versions = {}
        self.url = url
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
                ssl_socket = create_session_pyopenssl(self.url, self.port, context)
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
        if not self.versions:
            return
        self.rating = max(self.versions.values())
