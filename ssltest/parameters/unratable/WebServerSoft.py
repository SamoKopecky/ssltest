import logging

import nmap3
import requests

from ...sockets.SocketAddress import SocketAddress

log = logging.getLogger(__name__)


class WebServerSoft:
    def __init__(self, address, scan_nmap):
        """
        Constructor

        :param SocketAddress address: Web server address
        :param bool scan_nmap: Scan with nmap
        """
        self.address = address
        self.scan_nmap = scan_nmap
        self.scans = []
        self.software = {}

    def scan_software_nmap(self):
        """
        Get the web server software with nmap wrapper

        Scan for all valid key values in the result and append
        them together
        """
        keys = ["product", "version"]
        nmap = nmap3.Nmap()
        log.info("Scanning webserver for version with nmap")
        result = nmap.scan_top_ports(
            self.address.url, args=f"-sV -p {self.address.port}"
        )

        values = []
        service = list(result.items())[0][1]["ports"][0]["service"]
        for key in keys:
            try:
                values.append(service[key])
            except KeyError:
                log.warning("Unable to find any software versions")
        self.software["nmap"] = " ".join(values)

    def scan_software_http(self):
        """
        Get web server software from HEAD response header
        """
        log.info("Scanning webserver for version using http headers")
        value = ""
        try:
            response = requests.head(
                f"https://{self.address.url}:{self.address.port}",
                timeout=3,
                headers={"Connection": "close"},
                verify=False,
            )
            value = response.headers["server"]
        except KeyError:
            log.warning("Unable to find server software")
        except (
            requests.exceptions.InvalidSchema,
            requests.exceptions.SSLError,
            requests.exceptions.ConnectionError,
            requests.exceptions.Timeout,
            requests.exceptions.ReadTimeout,
        ):
            log.warning(
                "Unable to connect to scan for server software (probably not supported protocol version)"
            )
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
