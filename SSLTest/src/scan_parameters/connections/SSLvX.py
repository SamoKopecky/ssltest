from ...utils import communicate_data_return_sock

from abc import ABC, abstractmethod


class SSLvX(ABC):
    def __init__(self, url, port):
        self.address = (url, port)
        self.protocol = ''
        self.cipher_suite = None
        self.certificate = None
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

    @abstractmethod
    def scan_version_support(self):
        """
        Check if SSLvX version is supported by the web server
        """
        pass

    @abstractmethod
    def parse_cipher_suite(self):
        """
        Parse the cipher suite from the client_hello response
        """
        pass

    @abstractmethod
    def parse_certificate(self):
        """
        Parse the certificate from the client_hello response
        """
        pass

    @abstractmethod
    def verify_cert(self):
        """
        Verify the parsed certificate
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
