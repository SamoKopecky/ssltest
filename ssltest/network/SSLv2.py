import logging
import random
import secrets
from struct import unpack

from cryptography.x509 import load_der_x509_certificate

from .SSLvN import SSLvN
from ..core.utils import read_json
from ..sockets.SocketAddress import SocketAddress

log = logging.getLogger(__name__)


class SSLv2(SSLvN):
    def __init__(self, address):
        """
        Constructor

        :param SocketAddress address: Webserver address
        """
        super().__init__(address)
        self.protocol = "SSLv2"
        self.server_cipher_suites = []
        # fmt: off
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
        # fmt: on
        self.client_hello += secrets.token_bytes(16)

    def is_supported(self):
        # No response to SSLv2 client hello
        if len(self.data) == 0:
            log.debug("No response to SSLv2 client hello")
            return False
        # Test if the response is Content type Alert (0x15)
        # and test if alert message is protocol version (0x46)
        elif self.data[0] == 0x15 and (self.data[6] == 0x28 or self.data[6] == 0x46):
            log.debug("Alert response to SSLv2 client hello")
            return False
        # Test if the handshake message type is server hello
        elif self.data[2] == 0x04:
            log.debug("SSLv2 client hello response accepted")
            return True
        return False

    def parse_cipher_suite(self):
        cipher_suites = read_json("cipher_suites_sslv2.json")
        certificate_len = unpack(">H", self.data[7:9])[0]
        cipher_spec_len = unpack(">H", self.data[9:11])[0]
        cipher_spec_begin_idx = 11 + 2 + certificate_len
        for idx in range(
            cipher_spec_begin_idx, cipher_spec_begin_idx + cipher_spec_len, 3
        ):
            self.server_cipher_suites.append(
                cipher_suites[
                    f"{SSLv2.int_to_hex_str(self.data[idx])},"
                    f"{SSLv2.int_to_hex_str(self.data[idx + 1])},"
                    f"{SSLv2.int_to_hex_str(self.data[idx + 2])}"
                ]
            )
        random_number = int(random.randint(0, len(self.server_cipher_suites) - 1))
        return self.server_cipher_suites[random_number]

    def parse_certificate(self):
        certificates = []
        certificate_length = unpack(">H", self.data[7:9])[0]
        certificate_in_bytes = self.data[13 : certificate_length + 13]
        certificates.append(load_der_x509_certificate(certificate_in_bytes))
        return certificates

    @staticmethod
    def int_to_hex_str(number):
        """
        Convert integer to hex string

        :param int number: Any integer number
        :return: Hex string of a number
        :rtype: str
        """
        return f"0x{number:02X}"
