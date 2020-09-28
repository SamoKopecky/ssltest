import ssl, socket


def get_cert_info():
    hostname = 'vutbr.cz'
    ctx = ssl.create_default_context()
    with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
        s.connect((hostname, 443))
        cert = s.cipher()

    return cert


if __name__ == '__main__':
    print(get_cert_info())
