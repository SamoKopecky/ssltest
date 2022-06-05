import random
import secrets
from struct import unpack

from cryptography.x509 import load_der_x509_certificate

from .SSLvX import SSLvX
from ..main.utils import read_json, Address


class SSLv2(SSLvX):
    def __init__(self, address, timeout):
        """
        Constructor

        :param Address address: Webserver address
        :param int timeout: Timout for connections
        """
        super().__init__(address, timeout)
        self.protocol = 'SSLv2'
        self.server_cipher_suites = []
        self.client_hello = bytes([
            0x80,  # No padding
            0x2e,  # Length
            0x01,  # Handshake Message Type
            0x00, 0x02,  # Version (SSLv2)
            0x00, 0x15,  # Cipher spec length
            0x00, 0x00,  # Session ID Length
            0x00, 0x10,  # Challenge Length
            # Cipher specs (each 3 bytes unlike SSLv3 and up)
            0x01, 0x00, 0x80, 0x02, 0x00, 0x80, 0x03, 0x00,
            0x80, 0x04, 0x00, 0x80, 0x05, 0x00, 0x80, 0x06,
            0x00, 0x40, 0x07, 0x00, 0xc0,
            # Challenge
            # 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            # 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])
        self.client_hello += secrets.token_bytes(16)

    def scan_protocol_support(self):
        # No response to SSLv2 client hello
        if len(self.response) == 0:
            return False
        # Test if the response is Content type Alert (0x15)
        # and test if alert message is protocol version (0x46)
        elif self.response[0] == 0x15 and (self.response[6] == 0x28 or self.response[6] == 0x46):
            return False
        # Test if the handshake message type is server hello
        elif self.response[2] == 0x04:
            return True
        return False

    def parse_cipher_suite(self):
        cipher_suites = read_json('cipher_suites_sslv2.json')
        certificate_len = unpack('>H', self.response[7:9])[0]
        cipher_spec_len = unpack('>H', self.response[9:11])[0]
        cipher_spec_begin_idx = 11 + 2 + certificate_len
        for idx in range(cipher_spec_begin_idx, cipher_spec_begin_idx + cipher_spec_len, 3):
            self.server_cipher_suites.append(
                cipher_suites[
                    f'{SSLv2.int_to_hex_str(self.response[idx])},'
                    f'{SSLv2.int_to_hex_str(self.response[idx + 1])},'
                    f'{SSLv2.int_to_hex_str(self.response[idx + 2])}'
                ])
        random_number = int(random.randint(
            0, len(self.server_cipher_suites) - 1))
        self.cipher_suite = self.server_cipher_suites[random_number]

    def parse_certificate(self):
        certificate_length = unpack('>H', self.response[7:9])[0]
        certificate_in_bytes = self.response[13:certificate_length + 13]
        self.certificates.append(
            load_der_x509_certificate(certificate_in_bytes))

    @staticmethod
    def int_to_hex_str(number):
        return f'0x{number:02X}'
