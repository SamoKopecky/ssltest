import nmap3
import requests
import urllib3
import time
import logging

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def discover_ports(website):
    """
    Scans the url for available ports

    :param website: url to be scanned
    :return: list of usable ports
    """
    print('Discovering ports...')
    nmap = nmap3.NmapHostDiscovery()
    # Scan with nmap for all open ports
    result = nmap.nmap_portscan_only(website)
    open_ports = [port['portid'] for port in list(result.items())[0][1]['ports']]
    usable_ports = []
    logging.debug(f'ports : {open_ports}')
    for port in open_ports:
        sleep = 0
        # Loop until there is a valid response or after 10 seconds
        while True:
            try:
                head = requests.head(f'https://{website}:{port}', timeout=5, verify=False,
                                     headers={'Connection': 'close'})
                if head.status_code < 400:
                    usable_ports.append(int(port))
                    break
            except requests.exceptions.SSLError:
                break
            except (requests.exceptions.ReadTimeout, requests.exceptions.Timeout):
                usable_ports.append(int(port))
                break
            except requests.exceptions.ConnectionError:
                if sleep >= 4:
                    break
                sleep += 1
            logging.debug(f'sleeping for {sleep}...')
            time.sleep(sleep)
    logging.debug(f'scanned ports : {usable_ports}')
    return usable_ports
