#!/usr/bin/python3

from scan_web_server.scan.Parameters import Parameters
from scan_web_server.scan.scan_webserver_versions import scan_versions
from ouput_text.parse_parameters import to_string

website = str(input("Webová adresa: ") or 'vutbr.cz')
scan_nmap = str(input("Skenovať z nmap ? (Y/N): ") or 'N')
parameters = Parameters(website)
parameters.scan()
web_server_versions = scan_versions(website, scan_nmap)

to_string(parameters, web_server_versions)
