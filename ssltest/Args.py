__version__ = "0.2.1"

import argparse


class Args:
    args, parser = None, None

    @staticmethod
    def parse_args():
        """
        Parse input options

        :return: Parsed arguments and the argument parser
        :rtype: tuple[argparse.Namespace, argparse.ArgumentParser]
        """
        sudo_ops = Args.get_sudo_ops()
        parser = argparse.ArgumentParser(add_help=False)
        required = parser.add_argument_group("required arguments")
        fix_config = parser.add_mutually_exclusive_group()
        required.add_argument("-u", "--url", metavar="url")
        parser.add_argument("-h", "--help", action="store_true", default=False)
        parser.add_argument(
            "-p", "--port", default=[443], type=int, nargs="+", metavar="port"
        )
        parser.add_argument(
            "-j",
            "--json",
            action="store",
            metavar="output_file",
            required=False,
            nargs="?",
            default=False,
        )
        parser.add_argument("-c", "--config", action="store", metavar="config_dir")
        parser.add_argument("-t", "--test", type=int, metavar="test_num", nargs="+")
        parser.add_argument("-sn", "--short-names", action="store_true", default=False)
        parser.add_argument("-cc", "--cert-chain", action="store_true", default=False)
        parser.add_argument(
            "-cs", "--cipher-suites", action="store_true", default=False
        )
        parser.add_argument("-ns", "--nmap-scan", action="store_true", default=False)
        parser.add_argument(
            sudo_ops["nd"][0], sudo_ops["nd"][1], action="store_true", default=False
        )
        parser.add_argument(
            sudo_ops["fc"][0], sudo_ops["fc"][1], action="store_true", default=False
        )
        fix_config.add_argument(
            sudo_ops["st"][0], sudo_ops["st"][1], action="store_true", default=False
        )
        fix_config.add_argument(
            sudo_ops["ss"][0], sudo_ops["ss"][1], action="store_true", default=False
        )
        parser.add_argument("-w", "--worst", action="store_true", default=False)
        parser.add_argument("-i", "--info", action="store_true", default=False)
        parser.add_argument("-d", "--debug", action="store_true", default=False)
        parser.add_argument(
            "-v", "--version", action="version", version=f"%(prog)s {__version__}"
        )
        return parser.parse_args(), parser

    @staticmethod
    def get_sudo_ops():
        """
        Get all possible sudo options formats

        :return: Sudo options dictionary
        :rtype: dict
        """
        sudo_ops = {
            "fc": ["-fc", "--fix-conf"],
            "nd": ["-nd", "--nmap-discover"],
            "ss": ["-ss", "--sudo-stdin"],
            "st": ["-st", "--sudo-tty"],
        }
        for key in sudo_ops.keys():
            sudo_ops[key].append("/".join(sudo_ops[key]))
        return sudo_ops
