import csv
import logging
from abc import ABC, abstractmethod

import requests
from OpenSSL import crypto

from ..sockets.SafeSocket import SafeSocket
from ..sockets.SocketAddress import SocketAddress

log = logging.getLogger(__name__)


class SSLvN(ABC):
    def __init__(self, address):
        """
        Constructor

        :param SocketAddress address: Webserver address
        """
        self.address = address
        self.protocol = ""
        self.data = b""
        self.client_hello = bytes([])

    def connect(self):
        """
        Send the initial client hello, return the response

        :return: Response to the client hello
        :rtype: bytes
        """
        with SafeSocket(self.address, "sslvn_scan") as sock:
            sock.send(self.client_hello)
            return sock.receive()

    def verify_cert(self):
        """
        Verifies the web servers certificate or web servers certificate chain

        OpenSSL's lib is used to verify the certificate or the certificate chain

        :return: Wheter the certificate is verified
        :rtype: bool
        """
        store = crypto.X509Store()
        ssl_certificates = [
            crypto.X509.from_cryptography(cert) for cert in self.certificates
        ]
        # Just one certificate present in the response
        endpoint_certificate = ssl_certificates[0]
        # A certificate chain is present in the response
        # only the intermediate certificates are saved to the store
        if len(ssl_certificates) > 1:
            for cert in ssl_certificates[1:]:
                store.add_cert(cert)
        mozilla_ca_certificates = self.get_mozilla_ca_store()
        for ca_certificate in mozilla_ca_certificates:
            store.add_cert(ca_certificate)
        store_context = crypto.X509StoreContext(store, endpoint_certificate)
        try:
            store_context.verify_certificate()
            return True
        except crypto.X509StoreContextError:
            return False

    @abstractmethod
    def is_supported(self):
        """
        Check if SSLvX version is supported by the web server

        Implemented in SSLv2 and SSLv3 classes

        :return: Whether this SSL version is supported
        :rtype: bool
        """
        pass

    @abstractmethod
    def parse_cipher_suite(self):
        """
        Parse the cipher suite from the client_hello response

        Implemented in SSLv2 and SSLv3 classes

        :return: Parsed cipher suite
        :rtype: str
        """
        pass

    @abstractmethod
    def parse_certificate(self):
        """
        Parse the certificate from the client_hello response

        Implemented in SSLv2 and SSLv3 classes

        :return: Parsed certificate
        :rtype: cryptography.x509.Certificate
        """
        pass

    @staticmethod
    def get_mozilla_ca_store():
        """
        Converts mozilla root certificates to OpenSSL X509 certificate format

        :return: Mozilla certificate root store
        :rtype: list[OpenSSL.crypto.X509]
        """
        certs = []
        store_download_url = "https://ccadb-public.secure.force.com/mozilla/IncludedRootsPEMCSV?TrustBitsInclude=Websites"
        log.info(f"Downloading certificate store from {store_download_url}")
        store_data = requests.get(url=store_download_url).content.decode()
        store_csv = csv.reader(store_data, delimiter='"')
        store_csv.__iter__().__next__()
        for row in store_csv:
            if len(row) == 0:
                continue
            certificate_data = row[0].replace("'", "")
            ssl_certificate = crypto.load_certificate(
                crypto.FILETYPE_PEM, certificate_data.encode()
            )
            certs.append(ssl_certificate)
        return certs
