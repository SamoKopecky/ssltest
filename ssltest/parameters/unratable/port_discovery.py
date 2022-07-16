import logging

import nmap3
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
log = logging.getLogger(__name__)


def discover_ports(url):
    """
    Scan a web server for all available https ports

    :param str url: Url to be scanned
    :return: Usable ports
    :rtype: list[int]
    """
    log.info("Discovering ports with nmap")
    nmap = nmap3.NmapScanTechniques()
    # Scan with nmap for all open ports
    result = nmap.nmap_syn_scan(url, args="-p1-65535")
    open_ports = [port["portid"] for port in list(result.items())[0][1]["ports"]]
    usable_ports = []
    log.info(f"Scanned ports by nmap : {open_ports}")
    for port in open_ports:
        while True:
            try:
                head = requests.head(
                    f"https://{url}:{port}",
                    timeout=3,
                    verify=False,
                    headers={"Connection": "close"},
                )
                if head.status_code < 400:
                    usable_ports.append(int(port))
                    log.debug(f"Port {port} valid")
                    break
            except (
                requests.exceptions.ReadTimeout,
                requests.exceptions.Timeout,
                requests.exceptions.ConnectionError,
                requests.exceptions.SSLError,
            ):
                log.debug(f"Port {port} invalid")
                break
    log.info(f"Found ports: {usable_ports}")
    return usable_ports
