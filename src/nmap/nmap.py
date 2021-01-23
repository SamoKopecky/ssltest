import nmap3
from pprint import pprint


# prototype
def scan_versions():
    nmap = nmap3.Nmap()
    result = nmap.scan_top_ports("nmap.org", args="-sV")
    print('version = ' + result['45.33.49.119']['ports'][4]['service']['version'])
