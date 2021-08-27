def is_server_hello(message):
    """
    Checks if the message is a server hello

    :param bytes message: Received message
    :return: Whether the message is a legit server hello msg
    :rtype: bool
    """
    # Server hello content type in record protocol
    try:
        if message[5] == 0x02 and message[0] == 0x16:
            return True
    except IndexError:
        return False
    return False
