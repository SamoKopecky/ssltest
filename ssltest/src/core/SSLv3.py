from struct import unpack

from cryptography.x509 import load_der_x509_certificate

from .ClientHello import ClientHello
from .SSLvX import SSLvX
from ..main.utils import bytes_to_cipher_suite, parse_cipher_suite, protocol_version_conversion, Address


class SSLv3(SSLvX):
    def __init__(self, address, timeout):
        """
        Constructor

        :param Address address: Webserver address
        :param int timeout: Timout for connections
        """
        super().__init__(address, timeout)
        self.protocol = 'SSLv3'
        self.client_hello = ClientHello(protocol_version_conversion(self.protocol)) \
            .construct_client_hello()

    def scan_protocol_support(self):
        if len(self.response) == 0:
            return False
        # Test if the response is Content type Alert (0x15)
        # and test if the alert message is handshake failure (0x28)
        # or protocol version alert (0x46)
        elif self.response[0] == 0x15 and (self.response[6] == 0x28 or self.response[6] == 0x46):
            return False
        elif self.response[0] == 0x16 and self.response[5] == 0x02:
            return True
        return False

    def parse_cipher_suite(self):
        if len(self.response) == 0:
            return
        cipher_suite_bytes = parse_cipher_suite(self.response)
        self.cipher_suite = bytes_to_cipher_suite(cipher_suite_bytes, 'IANA')

    def parse_certificate(self):
        if len(self.response) == 0:
            return
        # Length is always at the same place in server_hello (idx 3, 4)
        server_hello_len = unpack('>H', self.response[3:5])[0]
        # +4 -- Length index in server_hello
        record_protocol_certificate_begin_idx = server_hello_len + 4 + 1
        # +5 -- Certificate index in record layer
        handshake_certificate_idx = record_protocol_certificate_begin_idx + 5
        # +7 -- Certificate length index in handshake protocol: certificate
        certs_len_idx = handshake_certificate_idx + 4
        certs_len = unpack(
            '>I', b'\x00' + self.response[certs_len_idx: certs_len_idx + 3])[0]

        offset = 0
        length_bytes = 3
        cert_len_idx = certs_len_idx + length_bytes
        # Loop until all certificate bytes are read
        while certs_len != 0:
            cert_len_idx += offset
            cert_len = unpack(
                '>I', b'\x00' + self.response[cert_len_idx: cert_len_idx + 3])[0]
            cert_idx = cert_len_idx + length_bytes
            offset = cert_len + length_bytes
            # Read bytes
            certs_len -= (cert_len + length_bytes)
            certificate_in_bytes = self.response[cert_idx:cert_len + cert_idx]
            self.certificates.append(
                load_der_x509_certificate(certificate_in_bytes))
