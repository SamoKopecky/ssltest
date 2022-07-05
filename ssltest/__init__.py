from .Args import Args
from .ConfigSetup import ConfigSetup
from .logging import logging_option

# This needs to be done here, if it's done in __main__,
# Scripy.py is already imported and that imports classes that
# run read_json from utils.py which depends on ConfigSetup
Args.args, Args.parser = Args.parse_args()
logging_option(Args.args)
ConfigSetup.install_configs()
ConfigSetup.custom_dir = Args.args.config
