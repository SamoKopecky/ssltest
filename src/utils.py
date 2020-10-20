import re


def get_oid_name(oid):
    return re.findall('name=[a-z, A-Z]+', oid)[0][5:]
