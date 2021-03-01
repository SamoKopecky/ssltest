import nmap3
import requests


class WebServerVersion:

    def __init__(self, website, ports, scan_nmap):
        self.scans = []
        self.ports = []
        self.versions = []
        self.website = website
        self.scan_nmap = scan_nmap
        self.set_port(ports)

    def set_port(self, ports):
        """
        Port setter method

        Method sets the just passes the port normally or creates
        one element array.
        :param ports: ports from constructor
        """
        if isinstance(ports, int):
            self.ports = [ports]
        else:
            self.ports = ports

    def scan_version_nmap(self):
        """
        Get the web server version with nmap wrapper.

        First ports are concatenated into a string for connection. After that
        for each port the result is looked up, if a version can't be found
        just skips to the next port.
        Appends triple value tuple of (nmap, port, extracted info) to the class
        list of scans.
        """
        keys = ['product', 'version']
        nmap = nmap3.Nmap()
        all_values = []

        ports = map(lambda port: f'{port}', self.ports)
        ports = ','.join(ports)

        print('Scanning webserver for version with nmap...')
        result = nmap.scan_top_ports(self.website, args=f"-sV -p {ports}")

        for index in range(len(self.ports)):
            values = []
            service = list(result.items())[0][1]['ports'][index]['service']
            for key in keys:
                try:
                    values.append(service[key])
                except KeyError:
                    error = 'unable to find'
                    if error not in values and not values:
                        values.append(error)
            all_values.append(("nmap", f'{self.ports[index]}', ','.join(values)))

        self.versions.extend(all_values)

    def scan_version_http(self):
        """
        Scan web server version from GET response headers.

        Cycles through ports and appends triple value
        tuple of (http_header, port, extracted info) to the class
        list of scans.
        """
        print('Scanning webserver for version using http headers...')
        all_values = []
        for port in self.ports:
            try:
                response = requests.head(f'https://{self.website}:{port}', timeout=5, headers={'Connection': 'close'})
                value = response.headers["server"]
            except KeyError:
                value = 'value not found'
            except (requests.exceptions.InvalidSchema,
                    requests.exceptions.SSLError,
                    requests.exceptions.ConnectionError,
                    requests.exceptions.Timeout,
                    requests.exceptions.ReadTimeout):
                value = 'unable to connect'
            all_values.append(("http_header", f'{port}', f'{value}'))

        self.versions.extend(all_values)

    def scan_versions(self):
        """
        Call the required functions to scan for webserver versions.
        """
        scans = []
        if self.website != '192.168.1.220':  # for testing purposes
            scans.append(self.scan_version_http)
        if self.scan_nmap:
            scans.append(self.scan_version_nmap)
        for scan in scans:
            scan()
