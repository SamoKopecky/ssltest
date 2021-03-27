import logging
from time import sleep, time
import socket


def receive_data(sock, timeout):
    """
    Receive data in chunks

    :param sock: socket to receive from
    :param timeout: timeout in seconds
    :return: array of bytes of received data
    """
    all_data = []
    begin = time()
    while 1:
        if all_data and time() - begin > timeout:
            logging.debug("timed out with received data")
            break
        elif time() - begin > timeout * 2:
            logging.debug("timed out with no received data")
            break
        try:
            data = sock.recv(2048)
            if data:
                logging.debug("receiving data")
                all_data.extend(data)
                begin = time()
            else:
                sleep(0.1)
        except socket.timeout:
            pass
    return bytes(all_data)


def send_client_hello(address, client_hello, timeout):
    """
    Send client client_hello to the server and catch the
    response

    :param address: tuple of an url and port
    :param client_hello: client_hello data in bytes
    :param timeout: timeout in seconds
    :return: created socket and received response
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect(address)
    sock.send(client_hello)
    response = receive_data(sock, 2)
    return response, sock
