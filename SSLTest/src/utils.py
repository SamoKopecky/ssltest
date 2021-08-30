import json
import logging
import os
import socket

from time import sleep, time


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
    :param int timeout: Timeout in seconds
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
        elif time() - begin > timeout * 2:
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
            pass
    return bytes(all_data)


def communicate_data_return_sock(address, client_hello, timeout, debug_source):
    """
    Send client client_hello to the server and catch the response

    :param tuple address: Tuple of an url and port
    :param bytes client_hello: client_hello data in bytes
    :param int timeout: Timeout in seconds
    :param str debug_source: Description of the debug source
    :return: Created socket and received response
    :rtype: bytes or socket
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sleep_dur = 0
    while True:
        try:
            sock.connect(address)
            break
        except socket.timeout:
            logging.debug('connection timeout...')
            sleep_dur = incremental_sleep(sleep_dur, Exception('Connection timeout'), 3)
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
