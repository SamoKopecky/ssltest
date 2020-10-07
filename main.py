import ssl, socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend


def get_cert_info():
    hostname = 'stackoverflow.com'
    ctx = ssl.create_default_context()

    with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as sslsock:
        sslsock.connect((hostname, 443))
        cert = sslsock.cipher()

    return cert


if __name__ == '__main__':
    cert_pem = bytes(ssl.get_server_certificate(('stackoverflow.com', 443)), 'utf-8')
    cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
    print(cert.signature_hash_algorithm.name)
    print(cert.not_valid_after)
    print(cert.not_valid_before)
    print(cert.issuer)
    print(cert.subject)
    print(cert.signature_algorithm_oid)
    print(get_cert_info())
    print("exponent : " + str(cert.public_key().public_numbers().e))
    print(cert.public_key().public_numbers().curve)

