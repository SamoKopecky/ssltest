import logging

from importlib.resources import path
from os import sep, mkdir
from os.path import exists
from pathlib import Path
from shutil import copy

configs = ['cipher_parameters.json', 'cipher_suites.json',
           'cipher_suites_sslv2.json', 'english_strings.json',
           'security_levels.json']

log = logging.getLogger(__name__)


def install_configs():
    """
    Install config files to the config dir
    """
    install_location = get_config_location()
    if not exists(install_location):
        mkdir(install_location)
    resource_dir = str(path('configs', configs[0]).parent)
    for file in configs:
        config_dest = f'{install_location}{sep}{file}'
        if not exists(config_dest):
            config_file = f'{resource_dir}{sep}{file}'
            log.debug(f'Copying {config_file} to {config_dest}')
            copy(config_file, config_dest)


def get_config_location():
    """
    Get the config location
    """
    return f'{str(Path.home())}{sep}.config{sep}ssltest'
