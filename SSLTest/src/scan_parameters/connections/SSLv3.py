from cryptography.x509 import load_der_x509_certificate

from ...utils import read_json, communicate_data_return_sock


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


class SSLv3:
    def __init__(self, url, port):
        self.address = (url, port)
        self.protocol = 'SSLv3'
        self.cipher_suite = None
        self.certificate = None
        self.cert_verified = None
        self.timeout = 2
        self.client_hello = bytes([
            # Record protocol
            0x16,  # Content type (Handshake)
            0x03, 0x00,  # Version (SSLv3)
            0x00, 0x8f,  # Length
            # Handshake protocol
            0x01,  # Handshake type
            0x00, 0x00, 0x8b,  # Length
            0x03, 0x00,  # Version
            # Random bytes
            0xa9, 0x09, 0x3f, 0x70, 0xad, 0xdc, 0xde, 0x4f,
            0xb1, 0x78, 0x47, 0xe5, 0xf3, 0x35, 0xea, 0xc9,
            0x1b, 0x3b, 0x34, 0x37, 0x23, 0xd8, 0xd4, 0x5d,
            0x92, 0x40, 0x4b, 0x01, 0x9e, 0x55, 0xf7, 0x2f,
            0x00,  # Session id length
            0x00, 0x64,  # Cipher suites length
            # Cipher suites
            0xc0, 0x14, 0xc0, 0x0a, 0x00, 0x39, 0x00, 0x38,
            0x00, 0x37, 0x00, 0x36, 0x00, 0x88, 0x00, 0x87,
            0x00, 0x86, 0x00, 0x85, 0xc0, 0x0f, 0xc0, 0x05,
            0x00, 0x35, 0x00, 0x84, 0xc0, 0x13, 0xc0, 0x09,
            0x00, 0x33, 0x00, 0x32, 0x00, 0x31, 0x00, 0x30,
            0x00, 0x9a, 0x00, 0x99, 0x00, 0x98, 0x00, 0x97,
            0x00, 0x45, 0x00, 0x44, 0x00, 0x43, 0x00, 0x42,
            0xc0, 0x0e, 0xc0, 0x04, 0x00, 0x2f, 0x00, 0x96,
            0x00, 0x41, 0x00, 0x07, 0xc0, 0x11, 0xc0, 0x07,
            0xc0, 0x0c, 0xc0, 0x02, 0x00, 0x05, 0x00, 0x04,
            0xc0, 0x12, 0xc0, 0x08, 0x00, 0x16, 0x00, 0x13,
            0x00, 0x10, 0x00, 0x0d, 0xc0, 0x0d, 0xc0, 0x03,
            0x00, 0x0a, 0x00, 0xff,
            0x01,  # Compression methods length
            0x00  # Compression methods
        ])
        self.response, _ = communicate_data_return_sock(self.address, self.client_hello, self.timeout, "SSLv3 scan")

    def scan_sslv3_version(self):
        # Test if the response is Content type Alert (0x15)
        # and test if the alert message is handshake failure (0x28)
        if self.response[0] == 0x15 and self.response[6] == 0x28:
            return False
        return True

    def parse_cipher_suite(self):
        cipher_suites = read_json('iana_cipher_suites.json')
        sess_id_len_idx = 43  # Always fixed
        cipher_suite_idx = self.response[sess_id_len_idx] + sess_id_len_idx + 1
        cipher_suites_bytes = f'0x{self.response[cipher_suite_idx]:X},' \
                              f'0x{self.response[cipher_suite_idx + 1]:X}'
        self.cipher_suite = cipher_suites[cipher_suites_bytes]

    def parse_certificate(self):
        # Length is always at the same place in server_hello (idx 3, 4)
        server_hello_len = hex_to_int([self.response[3], self.response[4]])
        # +4 -- Length index in server_hello
        record_protocol_certificate_begin_idx = server_hello_len + 4 + 1
        # +5 -- Certificate index in record layer
        handshake_certificate_idx = record_protocol_certificate_begin_idx + 5
        # +7 -- Certificate length index in handshake protocol: certificate
        certificate_len_idx = handshake_certificate_idx + 7
        certificate_len = hex_to_int([
            self.response[certificate_len_idx],
            self.response[certificate_len_idx + 1],
            self.response[certificate_len_idx + 2]
        ])
        certificate_idx = certificate_len_idx + 3
        certificate_in_bytes = self.response[certificate_idx:certificate_len + certificate_idx]
        self.certificate = load_der_x509_certificate(certificate_in_bytes)

    def verify_cert(self):
        self.cert_verified = False
