from ..utils import *


def construct_client_hello():
    client_hello = bytes([
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
    return client_hello


def scan(address):
    client_hello = construct_client_hello()
    timeout = 2
    server_hello, sock = send_client_hello(address, client_hello, timeout)
    # Test if the response is Content type Alert (0x15)
    # and test if the alert message is handshake failure (0x28)
    if server_hello[0] == 0x15 and server_hello[6] == 0x28:
        return False
    return True
