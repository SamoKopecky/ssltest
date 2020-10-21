import ssl
from src.utils import *
from socket import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend


def get_website_info(hostname):
    ssl_socket = create_session(hostname)
    get_session_info(ssl_socket)
    get_certificate_info(ssl_socket)


def get_certificate_info(ssl_socket):
    cert_pem = bytes(ssl_socket.getpeercert(binary_form=True))
    cert = x509.load_der_x509_certificate(cert_pem, default_backend())
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


def get_session_info(ssl_socket):
    cipher = ssl_socket.cipher()
    cipher_suite = cipher[0]
    if '-' in cipher_suite:
        cipher_suite = convert_openssh_to_iana(cipher_suite)
    print("Cipher suite : " + cipher_suite)
    print("TLS/SSL version : " + cipher[1])
    return ssl_socket


def create_session(hostname):
    ctx = ssl.create_default_context()
    ssl_socket = ctx.wrap_socket(socket(), server_hostname=hostname)
    ssl_socket.connect((hostname, 443))
    ssl_socket.getpeercert()
    return ssl_socket
