import nmap3
import requests
import urllib3
import logging

from ...utils import incremental_sleep

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def discover_ports(url):
    """
    Scan a web server for all available https ports

    :param str url: Url to be scanned
    :return: Usable ports
    :rtype: list
    """
    logging.info('Discovering ports...')
    nmap = nmap3.NmapHostDiscovery()
    # Scan with nmap for all open ports
    logging.debug('Scanning with nmap for all open ports...')
    result = nmap.nmap_portscan_only(url)
    open_ports = [port['portid'] for port in list(result.items())[0][1]['ports']]
    usable_ports = []
    logging.debug(f'ports : {open_ports}')
    for port in open_ports:
        sleep = 0
        # Loop until there is a valid response or after 10 seconds
        while True:
            try:
                head = requests.head(f'https://{url}:{port}', timeout=5, verify=False,
                                     headers={'Connection': 'close'})
                if head.status_code < 400:
                    usable_ports.append(int(port))
                    break
            except requests.exceptions.SSLError:
                break
            # Valid exception, there might a port alive after timeout
            except (requests.exceptions.ReadTimeout, requests.exceptions.Timeout):
                usable_ports.append(int(port))
                break
            except requests.exceptions.ConnectionError as exception:
                sleep = incremental_sleep(sleep, exception, 5)
    logging.debug(f'scanned ports : {usable_ports}')
    return usable_ports
