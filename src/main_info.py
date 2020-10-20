import OpenSSL.SSL as openssl
from src.utils import *
from socket import socket


def get_website_info(hostname):
    session = create_session(hostname)
    get_certificate_info(session)
    get_session_info(session)


def get_certificate_info(session: openssl.Connection):
    cert = session.get_peer_certificate()
    print("Certificate version: " + str(cert.get_version()))
    print("Serial Number: " + str(cert.get_serial_number()))
    print("Signature Algorithm: " + str_utf8(cert.get_signature_algorithm()))
    print("Asymmetric cryptography key length : " + str(cert.get_pubkey().bits()) + " bits")
    print("Validity interval: " + str(cert.get_notBefore(), 'utf-8') + " to " + str(cert.get_notAfter()))
    print('subject: ')
    for attribute in cert.get_subject().get_components():
        print(str_utf8(attribute[0]) + ' = ' + str_utf8(attribute[1]))
    print('issuer:')
    for attribute in cert.get_issuer().get_components():
        print(str_utf8(attribute[0]) + ' = ' + str_utf8(attribute[1]))


def get_session_info(session):
    print("Cipher suite : " + session.get_cipher_name())
    print("TLS/SSL version : " + session.get_protocol_version_name())


def create_session(hostname):
    sock = socket()
    context = openssl.Context(openssl.TLSv1_2_METHOD)
    connection = openssl.Connection(context, sock)
    connection.connect((hostname, 443))
    connection.do_handshake()
    return connection
