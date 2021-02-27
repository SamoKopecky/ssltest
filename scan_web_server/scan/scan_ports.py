import nmap3
import requests
import urllib3
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def scan_ports(website):
    """
    TODO: tweak nmap
    """
    print('Scanning for ports...')
    nmap = nmap3.NmapHostDiscovery()
    result = nmap.nmap_portscan_only(website)
    ports = [port['portid'] for port in list(result.items())[0][1]['ports']]
    usable_ports = []
    print(f'ports : {ports}')
    for port in ports:
        try:
            print(f'scanning port {port}')
            head = requests.head(f'https://{website}:{port}', timeout=5, verify=False)
            if head.status_code < 400:
                usable_ports.append(int(port))
        except (requests.exceptions.SSLError,
                requests.exceptions.ConnectionError):
            continue
    # time.sleep(2)
    print(f'usable ports : {usable_ports}')
    return usable_ports
