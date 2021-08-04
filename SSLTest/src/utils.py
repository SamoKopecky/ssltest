import os, json


def read_json(file_name: str):
    """
    Read a json file and return its content.

    :param file_name: json file name
    :return: json data in python objects
    """
    root_dir = os.path.dirname(os.path.abspath(__file__))
    file = open(f'{root_dir}/../../resources/{file_name}', 'r')
    json_data = json.loads(file.read())
    file.close()
    return json_data
