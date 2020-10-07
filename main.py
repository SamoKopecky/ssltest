import ssl, socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa


def get_website_info():
    hostname = 'vutbr.cz'
    cipher_suite = get_session_info(hostname)
    print("Info for " + hostname + ": ")
    cert_pem = bytes(ssl.get_server_certificate((hostname, 443)), 'utf-8')
    cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
    print("Certificate Hash algorith : " + cert.signature_hash_algorithm.name)
    print(get_cert_auth_algorithm(cert.public_key()))
    print("Certificate valid until : " + str(cert.not_valid_after.date()))
    print('subject: ')
    # TODO: nice printing
    for attribute in cert.subject:
        print(attribute.oid, end="")
        print(' = ' + attribute.value)
    print('issuer:')
    for attribute in cert.issuer:
        print(attribute.oid, end="")
        print(' = ' + attribute.value)
    print(cert.signature_algorithm_oid)
    print("Cipher suite : " + cipher_suite[0])
    print("TLS/SSL version : " + cipher_suite[1])


def get_cert_auth_algorithm(public_key):
    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA key size: " + str(public_key.key_size)
    # TODO: implement more algorithms


def get_session_info(hostname):
    hostname = hostname
    ctx = ssl.create_default_context()
    with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as sslsock:
        sslsock.connect((hostname, 443))
        cert = sslsock.cipher()

    return cert


if __name__ == '__main__':
    get_website_info()
