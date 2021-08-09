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
        self.response, _ = communicate_data_return_sock(self.address, self.client_hello, self.timeout,
                                                        self.__class__.__name__)

    @abstractmethod
    def scan_version_support(self):
        pass

    @abstractmethod
    def parse_cipher_suite(self):
        pass

    @abstractmethod
    def parse_certificate(self):
        pass

    @abstractmethod
    def verify_cert(self):
        pass

    @staticmethod
    def hex_to_int(hex_num: list):
        result = '0x'
        # {}:02x:
        # {}: -- value
        # 0 -- padding with zeros
        # 2 -- number digits
        # x -- hex format
        for num in hex_num:
            result += f'{num:02x}'
        return int(result, 16)
