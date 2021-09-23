import secrets
import ssl

from struct import pack

from ...utils import cipher_suite_to_bytes, read_json, protocol_version_conversion


class ClientHello:
    def __init__(self, protocol, cipher_suites=None, fill_cipher_suites=True):
        self.protocol = protocol
        self.str_protocol = protocol_version_conversion(protocol, False)
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
        # Fill random bytes
        self.handshake_protocol[2:34] = secrets.token_bytes(32)
        self.cipher_suites = self.pack_cipher_suite_bytes(cipher_suites, fill_cipher_suites)
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
        if self.str_protocol == 'TLSv1.3':
            # It is specified in RFC8446 that TLSv1.3 uses TLSv1.2 protocol version
            # number in the client hello, TLSv1.3 is specified by the supported versions
            # extension
            tls_v12_number = protocol_version_conversion('TLSv1.2', True)
            self.record_protocol[2] = tls_v12_number
            self.handshake_protocol[1] = tls_v12_number
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
            cipher_suites += custom_cipher_suites
        if fill_cipher_suites:
            cipher_suites += self.get_cipher_suites_for_version(self.str_protocol)
        return pack('>H', len(cipher_suites)) + cipher_suites

    @staticmethod
    def get_cipher_suites_for_version(str_version):
        """
        Extract cipher suites from ssl lib or json file

        :param str_version: SSL/TLS protocol version
        :return: Cipher suite bytes
        :rtype: bytearray
        """
        if str_version == 'TLSv1.1':
            str_version = 'TLSv1.0'
        ciphers = bytearray([])
        if str_version == 'SSLv3' or str_version == 'TLSv1.3':
            json_ciphers = read_json('cipher_suite_bytes.json')
            cipher_bytes = json_ciphers[str_version].split(',')
            for byte in cipher_bytes:
                ciphers += bytearray([int(byte, 16)])
        else:
            ctx = ssl.SSLContext()
            ctx.set_ciphers('ALL')
            for cipher in ctx.get_ciphers():
                if cipher['protocol'] == str_version:
                    ciphers += cipher_suite_to_bytes(cipher['name'], 'OpenSSL')
        return ciphers
