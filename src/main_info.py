import ssl
from src.utils import *
from socket import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend


def get_website_info(hostname):
    get_certificate_info(hostname)
    get_session_info(hostname)


def get_certificate_info(hostname):
    cert_pem = bytes(ssl.get_server_certificate((hostname, 443)), 'utf-8')
    cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
    print("Certificate version: " + str(cert.version.value))
    print("Serial Number: " + str(cert.serial_number))
    print("Signature Algorithm: " + str(cert.signature_algorithm_oid._name))
    print("Asymmetric cryptography key length : " + str(cert.public_key().key_size) + " bits")
    print("Validity interval: " + str(cert.not_valid_before.date()) + " to " + str(cert.not_valid_after.date()))
    print('subject: ')
    for attribute in cert.subject:
        print(attribute.oid._name + ' = ' + attribute.value)
    print('issuer:')
    for attribute in cert.issuer:
        print(attribute.oid._name + ' = ' + attribute.value)


def get_session_info(hostname):
    session = create_session(hostname)
    cipher_suite = session.cipher()
    print("Cipher suite : " + cipher_suite[0])
    print("TLS/SSL version : " + cipher_suite[1])


def create_session(hostname):
    ctx = ssl.create_default_context()
    ssl_socket = ctx.wrap_socket(socket(), server_hostname=hostname)
    ssl_socket.connect((hostname, 443))
    return ssl_socket
