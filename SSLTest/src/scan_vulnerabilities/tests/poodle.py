import logging
import socket

from OpenSSL import SSL

from ..utils import is_server_hello
from ...utils import communicate_data_return_sock


def construct_client_hello(version):
    client_hello = bytes([
        # Record protocol
        0x16,  # Content type (Handshake)
        0x03, version,  # Version
        0x00, 0xfb,  # Length
        # Handshake protocol
        0x01,  # Handshake type
        0x00, 0x00, 0xf7,  # Length
        0x03, version,  # TLS version
        # Random bytes
        0xf0, 0x36, 0x90, 0x63, 0x5a, 0x8c, 0xea, 0xaf,
        0xc5, 0x30, 0xcc, 0x46, 0x37, 0x8d, 0x95, 0x87,
        0x25, 0xff, 0xa6, 0xf2, 0x68, 0xa1, 0x51, 0xe8,
        0x2e, 0x2c, 0x7e, 0x6f, 0xd4, 0xaf, 0x05, 0xa2,
        0x20,  # Session id length
        # Session ID
        0x1a, 0xfb, 0x28, 0xdd, 0x4e, 0x50, 0x0d, 0xdf,
        0x0c, 0xe1, 0xa3, 0xd6, 0x8c, 0x9d, 0x59, 0x7b,
        0x09, 0xd0, 0x67, 0x94, 0x29, 0x92, 0x1e, 0xbd,
        0x72, 0x0b, 0x42, 0xec, 0x00, 0x44, 0x27, 0x73,
        0x00, 0x70,  # Cipher suites length
        # Most (not all) of CBC only cipher suites
        0x00, 0x07, 0x00, 0x09, 0x00, 0x0A, 0x00, 0x0C,
        0x00, 0x0D, 0x00, 0x0F, 0x00, 0x10, 0x00, 0x12,
        0x00, 0x13, 0x00, 0x15, 0x00, 0x16, 0x00, 0x2F,
        0x00, 0x30, 0x00, 0x31, 0x00, 0x32, 0x00, 0x33,
        0x00, 0x35, 0x00, 0x36, 0x00, 0x37, 0x00, 0x38,
        0x00, 0x39, 0x00, 0x3C, 0x00, 0x3D, 0x00, 0x3E,
        0x00, 0x3F, 0x00, 0x40, 0x00, 0x67, 0x00, 0x68,
        0x00, 0x69, 0x00, 0x6A, 0x00, 0x6B, 0x00, 0x96,
        0x00, 0x97, 0x00, 0x98, 0x00, 0x99, 0x00, 0x9A,
        0xC0, 0x03, 0xC0, 0x04, 0xC0, 0x05, 0xC0, 0x08,
        0xC0, 0x09, 0xC0, 0x0A, 0xC0, 0x0D, 0xC0, 0x0E,
        0xC0, 0x0F, 0xC0, 0x12, 0xC0, 0x13, 0xC0, 0x14,
        0xC0, 0x23, 0xC0, 0x24, 0xC0, 0x25, 0xC0, 0x26,
        0xC0, 0x27, 0xC0, 0x28, 0xC0, 0x29, 0xC0, 0x2A,
        0x01,  # Compression method length
        0x00,  # Compression method
        0x00, 0x3e,  # Extension length
        # Supported groups
        0x00, 0x0a, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x1d,
        0x00, 0x17, 0x00, 0x1e, 0x00, 0x19, 0x00, 0x18,
        # Signature algorithm
        0x00, 0x0d, 0x00, 0x2a, 0x00, 0x28, 0x04, 0x03,
        0x05, 0x03, 0x06, 0x03, 0x08, 0x07, 0x08, 0x08,
        0x08, 0x09, 0x08, 0x0a, 0x08, 0x0b, 0x08, 0x04,
        0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01,
        0x06, 0x01, 0x03, 0x03, 0x03, 0x01, 0x03, 0x02,
        0x04, 0x02, 0x05, 0x02, 0x06, 0x02
    ])
    return client_hello


def build_data(data):
    data_bytes = bytes([
        0x17,  # Content type (data)
        0x03, 0x03,  # Version
        0x00, 0x20,  # Length
        # Data (32 bytes)
        0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, data,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ])
    return data_bytes


def scan(address, version):
    """
    Not finished yet, just analyzing if the web server supports
    any CBC ciphers
    :param address: tuple of an url and port
    :param version: tls version in bytes
    :return: if the server is vulnerable
    """
    client_hello = construct_client_hello(version)
    logging.info("Scanning Poodle vulnerability...")
    server_hello, sock = communicate_data_return_sock(address, client_hello, 2)
    # If no server hello is sent the server doesn't support
    # CBC ciphers
    if not is_server_hello(server_hello):
        return False
    sock.close()
    unsafe_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssl_socket = SSL.Connection(SSL.Context(SSL.SSLv23_METHOD), unsafe_sock)
    ssl_socket.connect(address)
    ssl_socket.do_handshake()
    for i in range(256):
        try:
            unsafe_sock.send(build_data(i))
            ssl_socket.read(2048)
        # Server didn't send an alert
        except (SSL.ZeroReturnError, SSL.SysCallError):
            continue
        # Server broke connection
        except BrokenPipeError:
            return False
        # Server sent an alert
        except SSL.Error as e:
            if e.args[0][0][2] == 'sslv3 alert bad record mac':
                continue
            # If there is an alert and its not bad record mac
            else:
                return True
        # Unknown exception
        except Exception as e:
            raise e
    logging.info("Poodle vulnerability scan done.")
    return False