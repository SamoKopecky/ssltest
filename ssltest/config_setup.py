import logging
from os import sep, mkdir
from os.path import exists
from pathlib import Path
from shutil import copy

from pkg_resources import resource_filename, resource_listdir

log = logging.getLogger(__name__)


def install_configs():
    """
    Install config files to the config dir
    """
    install_location = get_config_location()
    if not exists(install_location):
        mkdir(install_location)
    configs_dir = resource_filename('ssltest', 'configs')
    configs = [file for file in resource_listdir('ssltest', 'configs')
               if not file.startswith('_')
               ]
    for file in configs:
        config_destination = f'{install_location}{sep}{file}'
        if not exists(config_destination):
            config_file = f'{configs_dir}{sep}{file}'
            log.debug(f'Copying {config_file} to {config_destination}')
            copy(config_file, config_destination)


def get_config_location():
    """
    Get the config location
    """
    return f'{str(Path.home())}{sep}.config{sep}ssltest'
