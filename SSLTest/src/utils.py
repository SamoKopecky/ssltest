import json
import logging
import os
import socket

from time import sleep, time
from typing import NamedTuple

from .exceptions.ConnectionTimeout import ConnectionTimeout


class Address(NamedTuple):
    url: str
    port: int


def read_json(file_name):
    """
    Read a json file and return its content

    :param str file_name: Json file name
    :return: Json data in python objects
    :rtype: dict
    """
    root_dir = os.path.dirname(os.path.abspath(__file__))
    file = open(f'{root_dir}/../../resources/{file_name}', 'r')
    json_data = json.loads(file.read())
    file.close()
    return json_data


def receive_data(sock, timeout, debug_source):
    """
    Receive network data in chunks

    :param sock: Socket to receive from
    :param float timeout: Timeout in seconds
    :param str debug_source: Description of the debug source
    :return: Array of bytes of received data
    :rtype: bytes
    """
    all_data = []
    begin = time()
    while 1:
        if all_data and time() - begin > timeout:
            logging.debug(f"({debug_source}) timed out with received data")
            break
        elif time() - begin > timeout:
            logging.debug(f"({debug_source}) timed out with no received data")
            break
        try:
            data = sock.recv(2048)
            if data:
                logging.debug(f"({debug_source}) receiving data")
                all_data.extend(data)
                begin = time()
            else:
                sleep(0.1)
        except (socket.timeout, ConnectionResetError):
            break
    return bytes(all_data)


def send_data_return_sock(address, client_hello, timeout, debug_source):
    """
    Send client client_hello to the server and catch the response

    :param Address address: Webserver address
    :param bytes client_hello: client_hello data in bytes
    :param float timeout: Timeout in seconds
    :param str debug_source: Description of the debug source
    :return: Created socket and received response
    :rtype: bytes or socket
    """
    sleep_dur = 0
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    while True:
        try:
            sock.connect(address)
            break
        except socket.timeout:
            sock.close()
            logging.debug('connection timeout...')
            raise ConnectionTimeout()
        except socket.error as e:
            logging.debug('error occurred...')
            sleep_dur = incremental_sleep(sleep_dur, e, 3)
    sock.send(client_hello)
    response = receive_data(sock, timeout, debug_source)
    return response, sock


def incremental_sleep(sleep_dur, exception, max_timeout_dur):
    """
    Sleeps for a period of time

    :param int sleep_dur: Sleep duration
    :param exception: Exception to be raised
    :param max_timeout_dur: Maximum amount of time to sleep
    :return: Next sleep duration
    :rtype: int
    """
    if sleep_dur >= max_timeout_dur:
        logging.debug('timed out')
        raise exception
    logging.debug('increasing sleep duration')
    sleep_dur += 1
    logging.debug(f'sleeping for {sleep_dur}')
    sleep(sleep_dur)
    return sleep_dur


# cipher_suites.json file was created using
# https://github.com/april/tls-table

def convert_cipher_suite(cipher_suite, from_cipher_suite, to_cipher_suite):
    """
    Convert one format of a cipher suite to another

    :param str cipher_suite: Cipher suite to be converted
    :param str from_cipher_suite: Format of the cipher suite
    :param str to_cipher_suite: Format to convert to
    :return: Converted cipher suite
    :rtype: str
    """
    json_data = read_json('cipher_suites.json')
    for cipher in json_data.values():
        if cipher[from_cipher_suite] == cipher_suite:
            return cipher[to_cipher_suite]
    raise Exception(f'No pair found for {cipher_suite}')


def bytes_to_cipher_suite(bytes_object, string_format):
    """
    Convert from cipher suite bytes to a cipher suite

    :param bytes bytes_object: Two bytes in an bytes object
    :param str string_format: Which cipher format to convert to
    :return: Cipher suite
    :rtype: str
    """
    if len(bytes_object) != 2:
        raise Exception(f'Can only convert from 2 bytes')
    bytes_string = f'0x{bytes_object[0]:02X},0x{bytes_object[1]:02X}'
    json_data = read_json('cipher_suites.json')
    for key, value in json_data.items():
        if key == bytes_string:
            return value[string_format]
    raise Exception(f'No cipher suite found for {bytes_string}')


def cipher_suite_to_bytes(cipher_suite, string_format):
    """
    Convert from string cipher suite to bytes

    :param str cipher_suite: String representation of a cipher suite
    :param str string_format: Which cipher format to convert from
    :return: Two bytes in an bytes object
    :rtype: bytes
    """
    json_data = read_json('cipher_suites.json')
    for key, value in json_data.items():
        if value[string_format] == cipher_suite:
            bytes_list = key.split(',')
            return bytes([int(bytes_list[0], 16), int(bytes_list[1], 16)])
    raise Exception(f'No bytes found for {cipher_suite}')


def parse_cipher_suite(data):
    """
    Extract the cipher suite out of a client hello

    :param data: Data to extract from
    :return: 2 cipher suite bytes
    :rtype: bytearray
    """
    sess_id_len_idx = 43  # Always fixed index
    cipher_suite_idx = data[sess_id_len_idx] + sess_id_len_idx + 1
    cipher_suites_bytes = data[cipher_suite_idx: cipher_suite_idx + 2]
    return bytearray(cipher_suites_bytes)


def protocol_version_conversion(version):
    """
    Convert SSL/TLS protocol version into the required format

    :param str or int version: SSL/TLS version, either in str or int
    :return: converted version
    :rtype: str or int
    """
    protocol_version_ints = {
        "TLSv1.3": 0x04,
        "TLSv1.2": 0x03,
        "TLSv1.1": 0x02,
        "TLSv1.0": 0x01,
        "SSLv3": 0x00
    }
    protocol_type = type(version)
    if protocol_type is str:
        return protocol_version_ints[version]
    elif protocol_type is int:
        return list(filter(lambda k: protocol_version_ints[k] == version, protocol_version_ints.keys()))[0]


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
