import logging
import ssl
from socket import socket, AF_INET, SOCK_STREAM, gaierror, error
from time import sleep

from .SafeSocket import SafeSocket

log = logging.getLogger(__name__)


class SecureSafeSocket(SafeSocket):
    def __init__(self, sock_addr, protocol, verify_cert, usage):
        """
        Constructor

        :param SocketAddress sock_addr: Socket address
        :param str protocol: TLS protocol version
        :param bool verify_cert: Whether to verify cert
        :param str usage: Network usage
        """
        self.protocol = protocol
        self.verify_cert = verify_cert
        self.cert_verified = False
        self.context = None
        super().__init__(sock_addr, usage)

    def __enter__(self):
        self.setup_context()
        return self

    def create_socket(self):
        """
        Wrap a socket into a secure context
        """
        sock = socket(AF_INET, SOCK_STREAM)
        sock.settimeout(self.timeout)
        self.sock = self.context.wrap_socket(sock, server_hostname=self.sock_addr.url)

    def connect(self):
        current_retry_interval = self.retry_interval
        correct_errors = [
            "[SSL: NO_PROTOCOLS_AVAILABLE]",
            "[SSL: SSLV3_ALERT_HANDSHAKE_FAILURE]",
            "[SSL: TLSV1_ALERT_PROTOCOL_VERSION]",
            "EOF occurred in violation of protocol",
            "[SSL: UNSUPPORTED_PROTOCOL]",
        ]
        for i in range(self.retries_count + 1):
            self.connection_end = False
            self.create_socket()
            try:
                self.sock.connect(self.sock_addr)
                log.debug("Connected")
                return True
            except ssl.SSLCertVerificationError:
                # If cert was unverified, connect again without verifying
                self.cert_verified = False
                self.context.check_hostname = False
                self.context.verify_mode = ssl.VerifyMode.CERT_NONE
            except gaierror:
                log.info("No DNS record found")
                raise Exception("DNS record not found")
            except Exception as exception:
                if isinstance(exception, error):
                    error_str = exception.args[1]
                    log.debug(error_str)
                    if any([m for m in correct_errors if m in error_str]):
                        log.debug("Connection refused")
                        return False

                log.warning(f"{exception}, retrying in {current_retry_interval} s...")
                sleep(current_retry_interval)
            finally:
                current_retry_interval = current_retry_interval * 2
        self.connection_end = True
        log.error("Number of retries exceeded limit, no longer trying again")

    def send(self, data):
        raise Exception("Not implemented")

    def receive(self):
        raise Exception("Not implemented")

    def setup_context(self):
        """
        Setup a secure context
        """
        self.create_ssl_context()
        self.cert_verified = True
        if not self.verify_cert:
            self.context.check_hostname = False
            self.context.verify_mode = ssl.VerifyMode.CERT_NONE
        self.context.set_ciphers("ALL")
        self.context.options |= ssl.OP_CIPHER_SERVER_PREFERENCE

    def create_ssl_context(self):
        """
        Create a ssl context from the native ssl library for the specific protocol version

        :return: Created SSL context
        :rtype: ssl.SSLContext
        """
        # fmt: off
        ssl_versions = {
            'TLSv1.0': ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_3 | ssl.OP_NO_SSLv3,
            'TLSv1.1': ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_3 | ssl.OP_NO_SSLv3,
            'TLSv1.2': ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_3 | ssl.OP_NO_SSLv3,
            'TLSv1.3': ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1 | ssl.OP_NO_SSLv3,
        }
        # fmt: on
        context = ssl.create_default_context()
        context.options = ssl.OP_ALL
        try:
            context.options |= ssl_versions[self.protocol]
        except KeyError:
            log.error(f"Unable to create context for {self.protocol}")
        self.context = context
