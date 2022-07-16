import logging
import sys


def logging_option(args):
    """
    Handle the debug and information options

    :param argparse.Namespace args: Parsed input arguments
    """
    logger = logging.getLogger(__package__)
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    if args.debug:
        ch.setLevel(logging.DEBUG)
    elif args.info:
        ch.setLevel(logging.INFO)
    else:
        logging.disable(sys.maxsize)
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    ch.setFormatter(formatter)
    logger.addHandler(ch)
