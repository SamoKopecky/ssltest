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


def version_conversion(version, from_string):
    """
    Convert SSL/TLS version into the required format

    :param str or int version: SSL/TLS version, either in str or int
    :param bool from_string: Convert from string or not
    :return: converted version
    :rtype: str or int
    """
    protocol_version_ints = {
        "TLSv1.3": 0x04,
        "TLSv1.2": 0x03,
        "TLSv1.1": 0x02,
        "TLSv1.0": 0x01,
        "SSLv3": 0x00
    }
    # TODO: fix
    if from_string:
        if version not in protocol_version_ints.keys():
            return -1
        return protocol_version_ints[version]
    else:
        if version not in protocol_version_ints.values():
            return ''
        keys = protocol_version_ints.keys()
        return list(filter(lambda key: protocol_version_ints[key] == version, keys))[0]
