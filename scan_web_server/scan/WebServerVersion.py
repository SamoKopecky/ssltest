import nmap3
import requests


class WebServerVersion:

    def __init__(self, url: str, port: int, scan_nmap: bool):
        self.scans = []
        self.port = port
        self.versions = {}
        self.url = url
        self.scan_nmap = scan_nmap

    def scan_version_nmap(self):
        """
        Get the web server version with nmap wrapper.

        Scans for all valid key values in the result and appends
        them together.
        """
        keys = ['product', 'version']
        nmap = nmap3.Nmap()
        print('Scanning webserver for version with nmap...')
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
        self.versions['nmap'] = ' '.join(values)

    def scan_version_http(self):
        """
        Scan web server version from HEAD response header.
        """
        print('Scanning webserver for version using http headers...')
        try:
            response = requests.head(f'https://{self.url}:{self.port}', timeout=3, headers={'Connection': 'close'})
            value = response.headers["server"]
        except KeyError:
            value = 'value not found'
        except (requests.exceptions.InvalidSchema,
                requests.exceptions.SSLError,
                requests.exceptions.ConnectionError,
                requests.exceptions.Timeout,
                requests.exceptions.ReadTimeout):
            value = 'unable to connect'
        self.versions["http_header"] = value

    def scan_versions(self):
        """
        Call the required functions to scan for webserver versions.
        """
        scans = []
        # for testing purposes TODO: delete later
        if self.url != '192.168.1.220':
            scans.append(self.scan_version_http)
        if self.scan_nmap:
            scans.append(self.scan_version_nmap)
        for scan in scans:
            scan()
