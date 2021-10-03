import json
import logging
import re
import sys
import traceback

from .scan import scan
from .scan_parameters.non_ratable.port_discovery import discover_ports
from .text_output.TextOutput import TextOutput


def run(args):
    """
    Call other functions to run the script

    :param Namespace args: Parsed input arguments
    """
    if '/' in args.url:
        args.url = fix_url(args.url)
    info_report_option(args)
    nmap_discover_option(args)
    output_data = scan_all_ports(args)
    out = output_option(args, output_data)
    if out: print(out)


def fix_url(url):
    """
    Extract the root domain name

    :param str url: Url of the web server
    :return: Fixed hostname address
    :rtype: str
    """
    logging.info('Correcting url...')
    if url[:4] == 'http':
        # Removes http(s):// and anything after TLD (*.com)
        url = re.search('[/]{2}([^/]+)', url).group(1)
    else:
        # Removes anything after TLD (*.com)
        url = re.search('^([^/]+)', url).group(0)
    logging.info('Corrected url: {}'.format(url))
    return url


def info_report_option(args):
    """
    Handle the debug and information options

    :param Namespace args: Parsed input arguments
    """
    if args.debug:
        logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    elif args.info:
        logging.basicConfig(stream=sys.stderr, level=logging.INFO)


def nmap_discover_option(args):
    """
    Handle discover ports option

    :param Namespace args: Parsed input arguments
    """
    scanned_ports = []
    if args.nmap_discover:
        try:
            scanned_ports = discover_ports(args.url)
        except Exception as ex:
            tb = traceback.format_exc()
            logging.debug(tb)
            print(f'Unexpected exception occurred: {ex}', file=sys.stderr)
        scanned_ports = list(filter(lambda p: p not in args.port, scanned_ports))
        args.port.extend(scanned_ports)


def scan_all_ports(args):
    """
    Call scan function for each port

    :param Namespace args: Parsed input arguments
    :return: Scanned data
    :rtype: dict
    """
    output_data = {}
    for port in args.port:
        try:
            output_data.update(scan(args, port))
        except Exception as ex:
            tb = traceback.format_exc()
            logging.debug(tb)
            print(f'Unexpected exception occurred: {ex}', file=sys.stderr)
    return output_data


def output_option(args, output_data):
    """
    Handle output depending on the input options

    :param Namespace args: Parsed input arguments
    :param dict output_data: Collected data from scanning/testing
    """
    json_output_data = json.dumps(output_data, indent=2)
    if args.json is False:
        text_output = TextOutput(json_output_data)
        text_output.get_formatted_text()
        return text_output.output
    elif args.json is None:
        return json_output_data
    else:
        file = open(args.json, 'w')
        file.write(json_output_data)
        file.close()
        print(f"Output writen to {args.json}", file=sys.stderr)
