from abc import ABC, abstractmethod


class SSLvX(ABC):
    def __init__(self, url, port):
        self.address = (url, port)
        self.protocol = ''
        self.cipher_suite = None
        self.certificate = None
        self.cert_verified = None
        self.timeout = 2
        self.client_hello = bytes([])

    @abstractmethod
    def scan_version_support(self):
        pass
