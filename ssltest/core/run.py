import json
import logging
import re
import sys
import traceback

from .scan import handle_scan_output
from ..parameters.unratable.port_discovery import discover_ports

log = logging.getLogger(__name__)


def run(args):
    """
    Call other functions to run the script, such as option handling

    :param argparse.Namespace args: Parsed script arguments
    """
    if "/" in args.url:
        args.url = fix_url(args.url)
    nmap_discover_option(args)
    json_data = scan_all_ports(args)
    if json_data:
        json_option(args, json_data)


def fix_url(url):
    """
    Extract the root domain name

    :param str url: Url of the web server
    :return: Fixed hostname address
    :rtype: str
    """
    log.warning("Url in incorrect format, correcting url")
    if url[:4] == "http":
        # Removes http(s):// and anything after TLD (*.com)
        url = re.search("[/]{2}([^/]+)", url).group(1)
    else:
        # Removes anything after TLD (*.com)
        url = re.search("^([^/]+)", url).group(0)
    log.info(f"Corrected url: {url}")
    return url


def nmap_discover_option(args):
    """
    Handle discover ports option

    :param argparse.Namespace args: Parsed script arguments
    """
    scanned_ports = []
    if args.nmap_discover:
        try:
            scanned_ports = discover_ports(args.url)
        except Exception as ex:
            tb = traceback.format_exc()
            log.debug(tb)
            print(f"Unexpected exception occurred: {ex}", file=sys.stderr)
        scanned_ports = list(filter(lambda p: p not in args.port, scanned_ports))
        # Hacky way to check if default value was used with -p option
        if 443 in args.port and any(scanned_ports):
            args.port = scanned_ports
        else:
            args.port.extend(scanned_ports)
        log.info(f"Ports to scan: {args.port}")


def scan_all_ports(args):
    """
    Scan each port

    :param argparse.Namespace args: Parsed script arguments
    :return: Scanned data
    :rtype: dict
    """
    output_data = {}
    if args.json is None:
        only_json = True
    else:
        only_json = False
    for port in args.port:
        try:
            output_data.update(handle_scan_output(args, port, only_json))
        except Exception as ex:
            tb = traceback.format_exc()
            log.debug(tb)
            print(f"\n\nUnexpected exception occurred: {ex}", file=sys.stderr)
    return output_data


def json_option(args, json_data):
    """
    Handle json option

    :param argparse.Namespace args: Parsed script arguments
    :param dict json_data: Collected data from scanning/testing
    """
    json_output_data = json.dumps(json_data, indent=2)
    if args.json is None:
        print(json_output_data)
    elif bool(args.json):
        file = open(args.json, "w")
        file.write(json_output_data)
        file.close()
        log.info(f"Output writen to {args.json}")
