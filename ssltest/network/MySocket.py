import logging
from socket import socket, AF_INET, SOCK_STREAM, SHUT_WR, timeout
from time import sleep

from .ProfileParser import ProfileParser
from .SocketAddress import SocketAddress

log = logging.getLogger(__name__)


class MySocket:

    def __init__(self, sock_addr, usage):
        """
        Init

        :param SocketAddress sock_addr:
        :param str usage:
        """
        self.sock_addr = sock_addr
        # Read from json
        self.sock: socket
        self.retries_count, self.retry_interval, self.network_timeout = \
            ProfileParser.parse(usage)
        self.connection_end = False
        self.connection_shutdown = False

    def __enter__(self):
        self.sock = socket(AF_INET, SOCK_STREAM)
        self.sock.settimeout(self.network_timeout)
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.connection_end:
            return
        self.close()

    def close(self):
        """
        Properly close a socket
        """
        self.connection_end = True
        if not self.connection_shutdown:
            self.sock.shutdown(SHUT_WR)
        self.sock.close()

    def shutdown(self):
        """
        Prevent further sending to the socket
        """
        self.connection_shutdown = True
        self.sock.shutdown(SHUT_WR)

    def connect(self):
        """
        Connect to address while retrying based on a json config
        """
        exceptions = (timeout, ConnectionResetError)
        current_retry_interval = self.retry_interval
        for i in range(self.retries_count + 1):
            try:
                self.sock.connect(self.sock_addr)
                return
            except exceptions as exception:
                log.warning(
                    f'{exception.strerror}, retrying in {current_retry_interval} ms...')
                sleep(current_retry_interval)
            finally:
                current_retry_interval = self.retry_interval * 2
        log.error('Number of retries exceeded limit, no longer trying again')

    def send(self, data):
        """
        Send data
        :param bytes data:
        """
        self.sock.send(data)

    def receive(self):
        """
        Receive data

        :return: Received data
        :rtype: bytes
        """
        chunks = []
        while True:
            try:
                chunk = self.sock.recv(2048)
            except timeout:
                break
            if chunk == b'':
                log.debug('Connection broken/ended')
                self.connection_end = True
                break
            chunks.append(chunk)
        return b''.join(chunks)
