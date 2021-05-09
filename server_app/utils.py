from flask import request
import json
import os


def parse_list(long_key, short_key):
    args = []
    values = request.form[long_key]
    if values != '':
        args.append(short_key)
        args.append(values)
    return args


def read_json(file_name: str):
    root_dir = os.path.dirname(os.path.abspath(__file__))
    file = open(f'{root_dir}/../resources/{file_name}', 'r')
    json_data = json.loads(file.read())
    file.close()
    return json_data


def translate_keys(obj):
    names = read_json('type_names.json')
    for key in list(obj.keys()):
        if key not in names.keys():
            continue
        new_key = names[key]
        if new_key != key:
            obj[new_key] = obj[key]
            del obj[key]
    return obj


def remove_invalid_values(data):
    for key, value in list(data.items()).copy():
        if type(value) is dict:
            if not data[key]:
                del data[key]
                continue
            keys_list = list(value.keys())
            if len(keys_list) > 0 and keys_list[0] == "N/A":
                del data[key]
                continue
            remove_invalid_values(value)
        else:
            return


def parse_checkboxes(switcher):
    checked = []
    for value in list(switcher.keys()):
        if value not in request.form:
            continue
        if request.form[value] == 'on':
            checked.append(switcher[value])
    return checked
