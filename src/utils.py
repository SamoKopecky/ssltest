import json
import os


def convert_openssh_to_iana(search_term):
    jdata = read_json('iana_openssl_cipher_mapping.json')
    for row in jdata:
        if jdata[row] == search_term:
            return row
    raise IndexError("cipher is not contained in .json file")


def read_json(file_name):
    root_dir = os.path.dirname(os.path.abspath(__file__))
    file = open(root_dir + '/../resources/' + file_name, 'r')
    jdata = json.loads(file.read())
    file.close()
    return jdata
