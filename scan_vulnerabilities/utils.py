from time import sleep, time
import socket


def receive_data(plain_sock, timeout):
    all_data = []
    begin = time()
    while 1:
        if all_data and time() - begin > timeout:
            break
        elif time() - begin > timeout * 2:
            break
        try:
            data = plain_sock.recv(2048)
            if data:
                all_data.extend(data)
                begin = time()
            else:
                sleep(0.1)
        except socket.timeout:
            pass
    return bytes(all_data)
