#!/usr/bin/env python3

import time

correct_openssl_conf = """
[default_conf]
ssl_conf = ssl_sect

[ssl_sect]
system_default = system_default_sect

[system_default_sect]
MinProtocol = TLSv1
CipherString = DEFAULT@SECLEVEL=0
"""


def fix_openssl_config():
    """
    Edit the OpenSSL config file

    Edit either the MinProtocol value in the openssl.cnf file or the CipherString
    value or insert booth of them with a prefix from the correct_openssl_conf.txt
    template file
    """
    config_file_name = "/etc/ssl/openssl.cnf"
    create_backup_config(config_file_name)
    config_file = open(config_file_name, "r")
    config_content = config_file.read()
    append = [False, False]

    min_protocol = "MinProtocol"
    cipher_string = "CipherString"
    if min_protocol in config_content:
        version = find_in_row("TLS", min_protocol, config_content)
        if version != "TLSv1":
            replace_string(config_file_name, version, "TLSv1")
    else:
        append[0] = True
    if cipher_string in config_content:
        cipher = find_in_row("DEFAULT", cipher_string, config_content)
        if cipher != "DEFAULT@SECLEVEL=0":
            replace_string(config_file_name, cipher, "DEFAULT@SECLEVEL=0")
    else:
        append[1] = True

    if append[0] or append[1]:
        correct_config = correct_openssl_conf
        with open(config_file_name, "w") as f:
            f.seek(0, 0)
            buffer = "openssl_conf = default_conf\n" + config_content
            buffer += correct_config
            f.write(buffer)
            f.flush()
    config_file.close()


def find_in_row(to_find, row_start, content):
    """
    Find a string in a row and return it until the end of the line

    :param str to_find: String to find
    :param str row_start: String representing the search start
    :param str content: Content to search through
    :return: Found string and the other content of the line
    :rtype: str
    """
    index = content.index(row_start)
    end_of_line = content.find("\n", index)
    to_find_index = content.find(to_find, index + len(row_start), end_of_line)
    return content[to_find_index:end_of_line]


def replace_string(file_name, to_replace, replace_with):
    """
    Replace a string in a file

    :param str file_name: Name of the file
    :param str to_replace: String to replace
    :param str replace_with: String to replace with
    """
    file_r = open(file_name, "r")
    content = file_r.read().replace(to_replace, replace_with)
    file_w = open(file_name, "w")
    file_w.write(content)
    file_w.flush()
    file_r.close()
    file_w.close()


def create_backup_config(file_path):
    """
    Back up the old config file

    :param str file_path: Config file path
    """
    old_file = open(file_path, "r")
    backup_file_path = file_path + f".backup_{time.time()}"
    backup_file = open(backup_file_path, "w")
    backup_file.write(old_file.read())
    old_file.close()
    backup_file.close()


if __name__ == "__main__":
    fix_openssl_config()
