import logging
from os import sep, mkdir, listdir
from os.path import exists
from pathlib import Path
from shutil import copy

from pkg_resources import resource_filename, resource_listdir

log = logging.getLogger(__name__)


class ConfigSetup:
    custom_dir = None
    install_dir = f"{str(Path.home())}{sep}.config{sep}ssltest"

    @classmethod
    def install_configs(cls):
        """
        Install config files to the config dir
        """
        if not exists(cls.install_dir):
            mkdir(cls.install_dir)
        configs_dir = resource_filename("ssltest", "configs")
        configs = [
            file
            for file in resource_listdir("ssltest", "configs")
            if not file.startswith("_")
        ]
        for file in configs:
            config_destination = f"{cls.install_dir}{sep}{file}"
            if not exists(config_destination):
                config_file = f"{configs_dir}{sep}{file}"
                log.debug(f"Copying {config_file} to {config_destination}")
                copy(config_file, config_destination)

    @classmethod
    def get_config_location(cls, file_name):
        """
        Get the config location

        :param str file_name: File name
        :return: Config installation directory
        :rtype: str
        """
        if cls.custom_dir is not None:
            opt_dir = listdir(cls.custom_dir)
            if file_name in opt_dir:
                return cls.custom_dir
        return cls.install_dir
