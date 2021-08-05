from .SSLvX import SSLvX
from ...utils import communicate_data_return_sock


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
        self.response, _ = communicate_data_return_sock(self.address, self.client_hello, self.timeout, "SSLv2 scan")

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
