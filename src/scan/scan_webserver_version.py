import nmap3
import requests
from src.custom_exceptions.CustomExceptions import NoWebServerVersionFoundError


def scan_version_nmap(website):
    """
    Gets the web server version with scan wrapper.

    First ports are concatenated into a string for scan. After that
    for each port the result is looked up, if a version can't be found
    just skips to the next port.
    :param: website: website to be scanned
    :return: if found returns web server version,
    if not returns error string
    """
    ports = [80, 443]
    nmap = nmap3.Nmap()
    ports = list(map(lambda port: str(port) + ',', ports))
    string_ports = ''.join(ports)[:-1]
    print('Skanujem pomocou nmap verziu web serveru...')
    result = nmap.scan_top_ports(website, args="-sV -p {}".format(string_ports))
    for index in range(len(ports)):
        try:
            service = list(result.items())[0][1]['ports'][index]['service']
            return str(service['product'] + '-' + service['version'])
        except KeyError:
            continue
    raise NoWebServerVersionFoundError()


def scan_version_http(website):
    """
    Scan web server version from GET response header.

    :param website: website to be scanned
    :return: returns web server name, if found version too
    """
    print('Skanujem HTTP response hlavičku pre webserver verziu...')
    response = requests.get('https://' + website)
    try:
        return response.headers['server']
    except KeyError:
        raise NoWebServerVersionFoundError()


def scan_versions(website, scan_nmap):
    """
    Use each function defined in scans list to
    find out web server versions.

    :param scan_nmap:
    :param website: website to be scanned
    :return: versions of the server, if it is not found returns
    exception error.
    """
    scans = []
    if website != '192.168.1.220':
        scans.append(scan_version_http)
    if scan_nmap != 'N' and scan_nmap != 'n':
        scans.append(scan_version_nmap)
    versions = []
    for scan in scans:
        try:
            versions.append(scan(website))
        except NoWebServerVersionFoundError as e:
            versions.append(e)
    return versions
