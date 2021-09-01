import random


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


def split_int_to_bytes(int_number, num_of_bytes):
    """
    Split one integer into byte sized integers

    Example: Return value for number 1892 and num_of_bytes 4:
    0x764 converted to hex and [0, 0, 7, 100] split into 4 bytes

    :param int int_number: Integer number to be split
    :param int num_of_bytes: Number of bytes, used for padding
    :return: Split integer
    :rtype: bytearray
    """
    hex_number = hex(int_number).replace('0x', '')
    # If the MSByte is missing a zero
    if len(hex_number) % 2 == 1:
        hex_number = '0' + hex_number
    result = [0] * (num_of_bytes - int(len(hex_number) / 2))
    for i in range(0, len(hex_number), 2):
        result.append(int(hex_number[i:i + 2], 16))
    return bytearray(result)


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
    if from_string:
        return protocol_version_ints[version]
    else:
        keys = protocol_version_ints.keys()
        return list(filter(lambda key: protocol_version_ints[key] == version, keys))[0]
