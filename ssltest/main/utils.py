import json
import logging
import re
import socket

from time import sleep, time
from typing import NamedTuple
from os import sep

from ..configs import get_config_location

log = logging.getLogger(__name__)


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
    root_dir = get_config_location()
    file_path = f'{root_dir}{sep}{file_name}'
    log.debug(f'Opening {file_path}')
    file = open(file_path, 'r')
    json_data = json.loads(file.read())
    file.close()
    return json_data


cipher_suites_json = read_json('cipher_suites.json')


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
    while True:
        try:
            data = sock.recv(2048)
            if data:
                log.debug(f'({debug_source}) receiving data')
                all_data.extend(data)
                begin = time()
            else:
                sleep(0.1)
        except socket.timeout:
            log.debug('Timeout out while receiving data')
            break
        if all_data and time() - begin > timeout:
            log.debug(f'({debug_source}) finished with received data')
            break
        elif time() - begin > timeout:
            log.debug(f'({debug_source}) finished with no received data')
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
            sock.send(client_hello)
            response = receive_data(sock, timeout, debug_source)
            break
        except socket.timeout as e:
            sock.close()
            log.warning(
                'Timeout out while creating socket and sending data, retrying')
            sleep_dur = incremental_sleep(sleep_dur, e, 2)
        except (socket.error, ConnectionResetError) as e:
            log.warning('Socket error occurred, retrying')
            sleep_dur = incremental_sleep(sleep_dur, e, 3)
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
        log.debug('timed out')
        raise exception
    sleep_dur += 1
    log.debug(f'increasing sleep duration to {sleep_dur}')
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
    for cipher in cipher_suites_json.values():
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
    bytes_string = cs_bytes_to_str(bytes_object)
    for key, value in cipher_suites_json.items():
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
    for key, value in cipher_suites_json.items():
        if value[string_format] == cipher_suite:
            bytes_list = key.split(',')
            return bytes([int(bytes_list[0], 16), int(bytes_list[1], 16)])
    raise Exception(f'No bytes found for {cipher_suite}')


def get_cipher_suite_protocols(cipher_suite):
    """
    Get a cipher suites supported protocols

    :param bytearray or bytes or str cipher_suite: cipher suite
    :return: list of supported protocols
    :rtype: list
    """
    if type(cipher_suite) == str:
        cipher_suite_to_bytes(cipher_suite, 'IANA')
    for key, value in cipher_suites_json.items():
        if key == cs_bytes_to_str(cipher_suite):
            return value['protocol_version'].split(',')


def cs_bytes_to_str(bytes_object):
    """
    Convert cipher suite bytes into string bytes

    e.g. bytes([192, 13]) => "0xC0,0x13"

    :param bytearray or bytes bytes_object: Pair of bytes representing a cipher suite
    :return: Converted string representation
    :rtype: str
    """
    return f'0x{bytes_object[0]:02X},0x{bytes_object[1]:02X}'


def filter_cipher_suite_bytes(cipher_suites, filter_regex):
    """
    Filters cipher suite bytes with the given filter function

    :param bytearray or bytes cipher_suites: Cipher suites
    :param lambda filter_regex: Regex to find the required cipher suites
    :return: Filter cipher suites
    :rtype: bytearray
    """
    filtered_suites = bytearray([])
    for i in range(0, len(cipher_suites), 2):
        cipher_suite_bytes = cipher_suites[i: i + 2]
        cipher_suite = bytes_to_cipher_suite(cipher_suite_bytes, 'IANA')
        regex_find = re.findall(filter_regex, cipher_suite)
        if len(regex_find) != 0:
            filtered_suites += cipher_suite_bytes
    return filtered_suites


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
    protocol_version = {
        'TLSv1.3': 0x04,
        'TLSv1.2': 0x03,
        'TLSv1.1': 0x02,
        'TLSv1.0': 0x01,
        'SSLv3': 0x00
    }
    protocol_type = type(version)
    if protocol_type is str:
        return protocol_version[version]
    elif protocol_type is int:
        return next(key for key, value in protocol_version.items() if value == version)


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
