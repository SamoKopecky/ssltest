import os, json


def read_json(file_name: str):
    """
    Read a json file and return its content.

    :param file_name: json file name
    :return: json data in python objects
    """
    root_dir = os.path.dirname(os.path.abspath(__file__))
    file = open(f'{root_dir}/../resources/{file_name}', 'r')
    json_data = json.loads(file.read())
    file.close()
    return json_data


def hex_to_int(hex_num: list):
    result = '0x'
    # {}:02x:
    # {}: -- value
    # 0 -- padding with zeros
    # 2 -- number digits
    # x -- hex format
    for num in hex_num:
        result += f'{num:02x}'
    return int(result, 16)
