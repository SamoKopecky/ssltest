import secrets
import ssl

from struct import pack

from .utils import version_conversion
from ..utils import cipher_suite_to_bytes, read_json


class ClientHello:
    def __init__(self, version, cipher_suites=None, fill_cipher_suites=True):
        self.version = version
        self.str_version = version_conversion(version, False)
        self.record_protocol = bytearray([
            0x16,  # Content type (Handshake)
            0x03, self.version,  # Version
            # 0x00, 0x00,  Length
        ])
        self.handshake_protocol_header = bytearray([
            0x01,  # Handshake type
            # 0x00, 0x00, 0x00,  Length
        ])
        self.handshake_protocol = bytearray([
            0x03, self.version,  # TLS version
            # Random bytes
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00,  # Session id length
        ])
        # Fill random bytes
        self.handshake_protocol[2:34] = secrets.token_bytes(32)
        self.cipher_suites = self.get_cipher_suite_bytes(cipher_suites, fill_cipher_suites)
        self.compression = bytearray([
            0x01,  # Compression method length
            0x00  # Compression method
        ])
        self.extensions = bytearray([
            # 0x00, 0x00,  Extensions length
            # Supported groups
            0x00, 0x0a, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x1d,
            0x00, 0x17, 0x00, 0x1e, 0x00, 0x19, 0x00, 0x18,
            # Signature algorithm
            0x00, 0x0d, 0x00, 0x2a, 0x00, 0x28, 0x04, 0x03,
            0x05, 0x03, 0x06, 0x03, 0x08, 0x07, 0x08, 0x08,
            0x08, 0x09, 0x08, 0x0a, 0x08, 0x0b, 0x08, 0x04,
            0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01,
            0x06, 0x01, 0x03, 0x03, 0x03, 0x01, 0x03, 0x02,
            0x04, 0x02, 0x05, 0x02, 0x06, 0x02,
        ])

    def construct_client_hello(self):
        """
        Concat all the client hello parts

        :return: Client hello bytes
        :rtype: bytearray
        """
        # Body of the client hello
        extensions_length = pack('>H', len(self.extensions))
        client_hello = self.handshake_protocol + self.cipher_suites + self.compression
        client_hello += extensions_length + self.extensions

        # Handshake protocol header
        length = pack('>I', len(client_hello))[1:]
        client_hello = self.handshake_protocol_header + length + client_hello

        # Record protocol
        length = pack('>H', len(client_hello))
        client_hello = self.record_protocol + length + client_hello
        return client_hello

    def get_cipher_suite_bytes(self, custom_cipher_suites, fill_cipher_suites):
        """
        Choose cipher suites based on the protocol version

        :param bool fill_cipher_suites:
        :param bytes or bytearray custom_cipher_suites: Additional cipher suites
        :return: Chosen ciphers
        :rtype: bytearray
        """
        cipher_suites = bytearray()
        if custom_cipher_suites is not None:
            cipher_suites += custom_cipher_suites
        if fill_cipher_suites:
            if 'SSLv3' == self.str_version:
                cipher_suites += self.ciphers_from_json_file()
            else:
                cipher_suites += self.ciphers_from_ssl_lib()
        return pack('>H', len(cipher_suites)) + cipher_suites

    def ciphers_from_ssl_lib(self):
        ciphers = bytes([])
        ctx = ssl.SSLContext()
        ctx.set_ciphers('ALL')
        for cipher in ctx.get_ciphers():
            if cipher['protocol'] == self.str_version:
                ciphers += cipher_suite_to_bytes(cipher['name'], 'OpenSSL')
        return ciphers

    def ciphers_from_json_file(self):
        ciphers = bytes([])
        json_ciphers = read_json('cipher_suite_bytes.json')
        cipher_bytes = json_ciphers[self.str_version].split(',')
        for byte in cipher_bytes:
            ciphers += bytes([int(byte, 16)])
        return ciphers
