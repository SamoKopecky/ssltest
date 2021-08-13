import requests
import csv

from ...utils import communicate_data_return_sock

from abc import ABC, abstractmethod
from OpenSSL import crypto


class SSLvX(ABC):
    def __init__(self, url, port):
        self.address = (url, port)
        self.protocol = ''
        self.cipher_suite = None
        self.certificates = []
        self.cert_verified = None
        self.timeout = 2
        self.response = b''
        self.client_hello = bytes([])

    def send_client_hello(self):
        """
        Send the initial client hello
        """
        self.response, _ = communicate_data_return_sock(self.address, self.client_hello, self.timeout,
                                                        self.__class__.__name__)

    def verify_cert(self):
        """
        Verifies the web servers certificate or web servers certificate chain

        OpenSSL lib is used to verify the certificate or the certificate chain
        """
        store = crypto.X509Store()
        ssl_certificates = [crypto.X509.from_cryptography(cert) for cert in self.certificates]
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
            self.cert_verified = True
        except crypto.X509StoreContextError:
            self.cert_verified = False

    @abstractmethod
    def scan_version_support(self):
        """
        Check if SSLvX version is supported by the web server

        Implemented in SSLv2 and SSLv3 classes
        """
        pass

    @abstractmethod
    def parse_cipher_suite(self):
        """
        Parse the cipher suite from the client_hello response

        Implemented in SSLv2 and SSLv3 classes
        """
        pass

    @abstractmethod
    def parse_certificate(self):
        """
        Parse the certificate from the client_hello response

        Implemented in SSLv2 and SSLv3 classes
        """
        pass

    @staticmethod
    def hex_to_int(hex_nums):
        """
        Convert pairs of hex into one number

        Return value for [0x25, 0x36]:
        0x2536 converted to int, so 9526 in decimal
        :param list hex_nums: Hex number pairs
        :return: Integer of the hex numbers
        :rtype: int
        """
        result = '0x'
        """
        num:02x
            num: -- value
            0 -- padding with zeros
            2 -- number digits
            x -- hex format
        """
        for num in hex_nums:
            result += f'{num:02x}'
        return int(result, 16)

    @staticmethod
    def get_mozilla_ca_store():
        """
        Converts mozilla root certificates to OpenSSL X509 certificate format

        :return: Mozilla certificate root store
        :rtype: list
        """
        certs = []
        store_download_url = \
            'https://ccadb-public.secure.force.com/mozilla/IncludedRootsPEMCSV?TrustBitsInclude=Websites'
        store_data = requests.get(url=store_download_url).content.decode()
        store_csv = csv.reader(store_data, delimiter='"')
        store_csv.__iter__().__next__()
        for row in store_csv:
            if len(row) == 0:
                continue
            certificate_data = row[0].replace('\'', '')
            ssl_certificate = crypto.load_certificate(crypto.FILETYPE_PEM, certificate_data.encode())
            certs.append(ssl_certificate)
        return certs
