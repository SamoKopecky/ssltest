#!/usr/bin/python3

def fix_openssl_config():
    config_file_name = '/etc/ssl/openssl.cnf'
    config_file = open(config_file_name, 'r')
    config_content = config_file.read()
    append = [False, False]

    min_protocol = 'MinProtocol'
    cipher_string = 'CipherString'
    if min_protocol in config_content:
        version = find_in_row('TLS', min_protocol, config_content)
        if version != 'TLSv1':
            replace_string(config_file_name, version, 'TLSv1')
    else:
        append[0] = True
    if cipher_string in config_content:
        cipher = find_in_row('DEFAULT', cipher_string, config_content)
        if cipher != 'DEFAULT@SECLEVEL=0':
            replace_string(config_file_name, cipher, 'DEFAULT@SECLEVEL=0')
    else:
        append[1] = True

    if append[0] or append[1]:
        correct_config_file = open('resources/correct_openssl_conf.txt', 'r')
        correct_config = correct_config_file.read()
        with open(config_file_name, 'w') as f:
            f.seek(0, 0)
            buffer = 'openssl_conf = default_conf\n' + config_content
            buffer += correct_config
            f.write(buffer)
            f.flush()
        correct_config_file.close()
    config_file.close()


def find_in_row(to_find, row_start, content):
    index = content.index(row_start)
    version_index = content.find(to_find, index + len(row_start), content.find('\n', index))
    return content[version_index:content.find('\n', index)]


def replace_string(file_name, string, replace_with):
    file_r = open(file_name, 'r')
    content = file_r.read().replace(string, replace_with)
    file_w = open(file_name, 'w')
    file_w.write(content)
    file_w.flush()
    file_r.close()
    file_w.close()


if __name__ == '__main__':
    fix_openssl_config()
