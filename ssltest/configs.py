from importlib.resources import path
import os
import shutil
from sys import platform
from os import sep

configs = ['cipher_parameters.json', 'cipher_suites.json',
           'cipher_suites_sslv2.json', 'english_strings.json',
           'security_levels.json']
linux_install_location = f'{os.getenv("HOME")}/.config/ssltest'


def install_configs():
    install_location = get_config_location()
    if not os.path.exists(install_location):
        os.mkdir(install_location)
    resource_dir = str(path('configs', configs[0]).parent)
    for file in configs:
        file_path = f'{install_location}{sep}{file}'
        if not os.path.exists(file_path):
            shutil.copy(f'{resource_dir}{sep}{file}', file_path)


def get_config_location():
    if platform == 'linux' or platform == 'linux2':
        return linux_install_location
    else:
        # TODO: Windows, macOS
        return ''
