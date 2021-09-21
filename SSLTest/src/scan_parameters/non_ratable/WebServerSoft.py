import logging

import nmap3
import requests


class WebServerSoft:

    def __init__(self, url: str, port: int, scan_nmap: bool):
        self.scans = []
        self.port = port
        self.software = {}
        self.url = url
        self.scan_nmap = scan_nmap

    def scan_software_nmap(self):
        """
        Get the web server software with nmap wrapper

        Scan for all valid key values in the result and append
        them together
        """
        keys = ['product', 'version']
        nmap = nmap3.Nmap()
        logging.info('Scanning webserver for version with nmap...')
        result = nmap.scan_top_ports(self.url, args=f"-sV -p {self.port}")

        values = []
        service = list(result.items())[0][1]['ports'][0]['service']
        for key in keys:
            try:
                values.append(service[key])
            except KeyError:
                error = 'unable to find'
                if error not in values and not values:
                    values.append(error)
        self.software['nmap'] = ' '.join(values)

    def scan_software_http(self):
        """
        Get web server software from HEAD response header
        """
        logging.info('Scanning webserver for version using http headers...')
        try:
            response = requests.head(f'https://{self.url}:{self.port}', timeout=3, headers={'Connection': 'close'},
                                     verify=False)
            value = response.headers["server"]
        except KeyError:
            value = 'value not found'
        except (requests.exceptions.InvalidSchema,
                requests.exceptions.SSLError,
                requests.exceptions.ConnectionError,
                requests.exceptions.Timeout,
                requests.exceptions.ReadTimeout):
            value = 'unable to connect (try scanning with nmap)'
        self.software["http_header"] = value

    def scan_server_software(self):
        """
        Call the required functions to scan the webserver software
        """
        scans = [self.scan_software_http]
        if self.scan_nmap:
            scans.append(self.scan_software_nmap)
        for scan in scans:
            scan()
