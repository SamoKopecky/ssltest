import random

from cryptography.x509 import load_der_x509_certificate

from .SSLvX import SSLvX
from ...utils import read_json


class SSLv2(SSLvX):
    def __init__(self, url, port):
        super().__init__(url, port)
        self.protocol = 'SSLv2'
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
            0xdc, 0x83, 0x85, 0x49, 0x87, 0xdf, 0x42, 0xad,
            0x84, 0x90, 0x51, 0x90, 0x00, 0x14, 0x33, 0xf6
        ])

    def scan_version_support(self):
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
        certificate_len = SSLvX.bytes_to_int([self.response[7], self.response[8]])
        cipher_spec_len = SSLvX.bytes_to_int([self.response[9], self.response[10]])
        cipher_spec_begin_idx = 11 + 2 + certificate_len
        server_cipher_suites = []
        for idx in range(cipher_spec_begin_idx, cipher_spec_begin_idx + cipher_spec_len, 3):
            server_cipher_suites.append(
                cipher_suites[
                    f'{SSLv2.int_to_hex_str(self.response[idx])},'
                    f'{SSLv2.int_to_hex_str(self.response[idx + 1])},'
                    f'{SSLv2.int_to_hex_str(self.response[idx + 2])}'
                ]
            )
        random_number = int(random.randint(0, len(server_cipher_suites) - 1))
        self.cipher_suite = server_cipher_suites[random_number]

    def parse_certificate(self):
        certificate_length = SSLvX.bytes_to_int([
            self.response[7],
            self.response[8]
        ])
        certificate_in_bytes = self.response[13:certificate_length + 13]
        self.certificates.append(load_der_x509_certificate(certificate_in_bytes))

    @staticmethod
    def int_to_hex_str(number):
        return f'0x{number:02X}'
