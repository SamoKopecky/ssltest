def is_server_hello(server_hello):
    # Server hello content type in record protocol
    try:
        if server_hello[5] != 0x02:
            return False
    except IndexError:
        return False
    return True
