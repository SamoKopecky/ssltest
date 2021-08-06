def is_server_hello(server_hello):
    # Server hello content type in record protocol
    try:
        if server_hello[5] == 0x02 and server_hello[0] == 0x16:
            return True
    except IndexError:
        return False
    return False
