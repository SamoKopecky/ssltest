import inspect
import json
import logging
import os
import socket

from time import sleep, time


def read_json(file_name: str):
    """
    Read a json file and return its content.

    :param file_name: json file name
    :return: json data in python objects
    """
    root_dir = os.path.dirname(os.path.abspath(__file__))
    file = open(f'{root_dir}/../../resources/{file_name}', 'r')
    json_data = json.loads(file.read())
    file.close()
    return json_data


def receive_data(sock, timeout, debug_source=None):
    """
    Receive data in chunks

    :param debug_source:
    :param sock: socket to receive from
    :param timeout: timeout in seconds
    :return: array of bytes of received data
    """
    if debug_source is None:
        stack = inspect.stack()
        full_test_name = stack[len(stack) - 6].filename
        # Get current test name for debugging purposes
        debug_source = full_test_name.split(os.path.sep)[-1]
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


def communicate_data_return_sock(address, client_hello, timeout, debug_source=None):
    """
    Send client client_hello to the server and catch the
    response

    :param debug_source:
    :param address: tuple of an url and port
    :param client_hello: client_hello data in bytes
    :param timeout: timeout in seconds
    :return: created socket and received response
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect(address)
    sock.send(client_hello)
    response = receive_data(sock, timeout, debug_source)
    return response, sock
