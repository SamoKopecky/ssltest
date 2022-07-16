import logging

from .PType import PType
from .Parameters import Parameters
from ...network.SSLv2 import SSLv2
from ...network.SSLv3 import SSLv3
from ...sockets.SecureSafeSocket import SecureSafeSocket
from ...sockets.SocketAddress import SocketAddress

log = logging.getLogger(__name__)


class ProtocolSupport:
    def __init__(self, address):
        """
        Constructor

        :param SocketAddress address: Webserver address
        """
        self.protocols = {PType.protocols: {}, PType.no_protocol: {}}
        self.supported = []
        self.unsupported = []
        self.address = address
        self.rating = 0

    def scan_protocols(self):
        """
        Test for all possible SSL/TLS versions which the server supports
        Convert protocol versions to dict with PType to get them ready for rating
        """
        log.info("Scanning supported SSL/TLS versions")
        self.scan_ssl_protocols()
        self.scan_tls_protocols()
        for protocol in self.supported:
            self.protocols[PType.protocols][protocol] = "N/A"
        for no_protocol in self.unsupported:
            self.protocols[PType.no_protocol][no_protocol] = "N/A"
        if len(self.supported) == 0:
            raise Exception("No SSL/TLS protocol support found")

    def scan_ssl_protocols(self):
        """
        Test for all possible SSL versions which the server supports
        """
        ssl_versions = [SSLv2, SSLv3]
        for ssl_version in ssl_versions:
            ssl_version = ssl_version(self.address)
            log.info(f"Scanning for {ssl_version.protocol}")
            ssl_version.data = ssl_version.connect()
            supported = ssl_version.is_supported()
            if supported:
                self.supported.append(ssl_version.protocol)
            else:
                self.unsupported.append(ssl_version.protocol)

    def scan_tls_protocols(self):
        """
        Test for all possible TLS versions which the server supports
        """
        tls_protocols = ["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
        for protocol in tls_protocols:
            log.info(f"Scanning for {protocol}")
            with SecureSafeSocket(
                self.address, protocol, False, "tlsv1.n_scan"
            ) as sock:
                supported = sock.connect()
            if not supported:
                self.unsupported.append(protocol)
                continue
            self.supported.append(protocol)

    def rate_protocols(self):
        """
        Rate the scanned protocols
        """
        for protocol in list(self.protocols[PType.protocols].keys()):
            self.protocols[PType.protocols][protocol] = Parameters.rate_parameter(
                PType.protocol, protocol
            )
        for no_protocol in list(self.protocols[PType.no_protocol].keys()):
            self.protocols[PType.no_protocol][no_protocol] = Parameters.rate_parameter(
                PType.no_protocol, no_protocol
            )
        if ["TLSv1.3"] == list(self.protocols[PType.protocols].keys()):
            self.protocols[PType.no_protocol]["TLSv1.2"] = "1"
        if not self.protocols:
            return
        ratings = list(self.protocols[PType.protocols].values()) + list(
            self.protocols[PType.no_protocol].values()
        )
        self.rating = max(ratings)

    def get_json(self):
        """
        Get supported protocols as json

        :return: Json version supported protocols
        :rtype: dict
        """
        protocols = {}
        keys = {key.name: value for key, value in self.protocols.items()}
        for key, value in list(keys.items()):
            protocols[key] = value
        protocols.update({"rating": self.rating})
        return protocols
