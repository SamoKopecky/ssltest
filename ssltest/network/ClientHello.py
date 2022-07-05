import logging
import secrets
from struct import pack

from ..core.utils import read_json, protocol_version_conversion

log = logging.getLogger(__name__)


class ClientHello:
    json_ciphers = read_json("cipher_suites.json")

    def __init__(self, protocol, cipher_suites=None, fill_cipher_suites=True):
        """
        Constructor

        :param int protocol: SSL/TLS protocol version
        :param bytes cipher_suites: Custom cipher suites
        :param bool fill_cipher_suites: Fill with default cipher suites
        """
        self.protocol = protocol
        self.str_protocol = protocol_version_conversion(protocol)
        # fmt: off
        self.record_protocol = bytearray([
            0x16,  # Content type (Handshake)
            0x03, self.protocol,  # Version
            # 0x00, 0x00,  Length
        ])
        self.handshake_protocol_header = bytearray([
            0x01,  # Handshake type
            # 0x00, 0x00, 0x00,  Length
        ])
        self.handshake_protocol = bytearray([
            0x03, self.protocol,  # TLS version
            # Random bytes
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00,  # Session id length
        ])
        self.compression = bytearray([
            0x01,  # Compression method length
            0x00  # Compression method
        ])
        self.extensions = bytearray([
            # 0x00, 0x00,  Extensions length
            # Supported groups
            0x00, 0x0a,  # Supported groups extension
            0x00, 0x0c,  # Length
            0x00, 0x0a,  # Supported groups length
            # Supported groups
            0x00, 0x1d, 0x00, 0x17, 0x00, 0x1e, 0x00, 0x19,
            0x00, 0x18,
            # Signature algorithms extension
            0x00, 0x0d,  # Signature algorithms extension
            0x00, 0x30,  # Length
            0x00, 0x2e,  # Signature algorithms length
            # Signature algorithms
            0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x07,
            0x08, 0x08, 0x08, 0x09, 0x08, 0x0a, 0x08, 0x0b,
            0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01,
            0x05, 0x01, 0x06, 0x01, 0x03, 0x03, 0x02, 0x03,
            0x03, 0x01, 0x02, 0x01, 0x03, 0x02, 0x02, 0x02,
            0x04, 0x02, 0x05, 0x02, 0x06, 0x02
        ])
        # fmt: on
        # Fill random bytes
        self.handshake_protocol[2:34] = secrets.token_bytes(32)
        self.cipher_suites = self.pack_cipher_suite_bytes(
            cipher_suites, fill_cipher_suites
        )
        if self.str_protocol == "TLSv1.3":
            # It is specified in RFC8446 that TLSv1.3 uses TLSv1.2 protocol version
            # number in the client hello, TLSv1.3 is specified by the supported versions
            # extension
            tls_v12_number = protocol_version_conversion("TLSv1.2")
            self.record_protocol[2] = tls_v12_number
            self.handshake_protocol[1] = tls_v12_number
            # fmt: off
            self.extensions += bytearray([
                # Supported versions extension
                0x00, 0x2b,  # Supported versions extension
                0x00, 0x03,  # Length
                0x02,  # Supported versions length
                0x03, 0x04,  # Supported versions (TLSv1.3)
                # Key share extension, required extensions for TLSv1.3
                0x00, 0x33,  # Key share extension
                0x00, 0x02,  # Length
                0x00, 0x00,  # Key share length
            ])
            # fmt: on

    def pack_client_hello(self):
        """
        Concat all the client hello parts

        :return: Client hello bytes
        :rtype: bytearray
        """
        log.debug("Constructing client hello")
        # Body of the client hello
        extensions_length = pack(">H", len(self.extensions))
        client_hello = self.handshake_protocol + self.cipher_suites + self.compression
        client_hello += extensions_length + self.extensions

        # Handshake protocol header
        length = pack(">I", len(client_hello))[1:]
        client_hello = self.handshake_protocol_header + length + client_hello

        # Record protocol
        length = pack(">H", len(client_hello))
        client_hello = self.record_protocol + length + client_hello
        return client_hello

    def pack_cipher_suite_bytes(self, custom_cipher_suites, fill_cipher_suites):
        """
        Packs the cipher suites based on the given cipher suites

        :param bytes or bytearray custom_cipher_suites: Additional cipher suites
        :param bool fill_cipher_suites: Whether to add usual protocol version cipher suites
        :return: Chosen cipher suites
        :rtype: bytearray
        """
        cipher_suites = bytearray()
        if custom_cipher_suites is not None:
            log.debug("Adding custom cipher suites")
            cipher_suites += custom_cipher_suites
        if fill_cipher_suites:
            log.debug("Adding usual protocol cipher suites")
            cipher_suites += self.get_cipher_suites_for_version(self.str_protocol)
        return pack(">H", len(cipher_suites)) + cipher_suites

    @classmethod
    def get_cipher_suites_for_version(cls, version):
        """
        Extract cipher suites from ssl lib or json file

        :param int or str version: SSL/TLS protocol version
        :return: Cipher suite bytes
        :rtype: bytearray
        """
        if type(version) == int:
            version = protocol_version_conversion(version)
        if version == "TLSv1.1":
            version = "TLSv1.0"
        ciphers = bytearray([])
        for key, value in cls.json_ciphers.items():
            if version in value["protocol_version"]:
                cs_bytes = key.split(",")
                ciphers += bytearray([int(cs_bytes[0], 16), int(cs_bytes[1], 16)])
        return ciphers

    @staticmethod
    def is_server_hello(message):
        """
        Checks if the message is a server hello

        :param bytes message: Received message
        :return: Whether the message is a legit server hello msg
        :rtype: bool
        """
        # Server hello content type in record protocol
        try:
            if message[5] == 0x02 and message[0] == 0x16:
                return True
        except IndexError:
            return False
        return False
