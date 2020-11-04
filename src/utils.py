import json
import os

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))


def convert_openssh_to_iana(search_term):
    jfile = open(ROOT_DIR + '/../resources/iana_openssl_cipher_mapping.json', 'r')
    jdata = json.loads(jfile.read())
    for row in jdata:
        if jdata[row] == search_term:
            return row
    jfile.close()
    raise IndexError("cipher is not contained in .json file")
