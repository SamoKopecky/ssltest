```
 ____            _                        _____           _     
|  _ \ ___ _ __ | |_ ___ _ __ ___ _ __   |_   _|__   ___ | |___ 
| |_) / _ \ '_ \| __/ _ \ '__/ _ \ '_ \    | |/ _ \ / _ \| / __|
|  __/  __/ | | | ||  __/ | |  __/ |_) |   | | (_) | (_) | \__ \
|_|   \___|_| |_|\__\___|_|  \___| .__/    |_|\___/ \___/|_|___/
                                 |_|
```

# SSLTest

A Python script that scans web servers cryptographic parameters and vulnerabilities. All available Vulnerability tests
can be found in the `help` output of the script or in the [options](#Options) section.

## Main features

- Supported SSL/TLS protocols
- Detailed information about the certificate
- Detailed information about the cipher suite the connection was made with
- Web server software used by the server
- Chosen vulnerability tests
- Supported cipher suites for all SSL/TLS protocols

## Dependencies

Dependencies are listed in the `requirements.txt` file, to install them use this:

```
$ pip3 install -r requirements.txt
```

Nmap is required for some functions of the script, install on ubuntu-like distros with:

```
$ sudo apt-get install -y nmap
```

## Installation

```
$ git clone SSLTest
$ cd SSLTest && sudo pip install .
```

## Installation (ptmanager)

```
$ sudo ptmanager -ut SSLTest
```

## Options

```
-u  --url       <url>        Url to scan, required option
-p  --port      <port ...>   Port or ports (separate with spaces) to scan on (default: [443])
-j  --json      <file>       change output to json format, if a file name is specified output is 
                             written to the given file
-t  --test      <number ...> Test the server for a specified vulnerability
                             possible vulnerabilities (separate with spaces):
                                    0: No test
                                    1: CCS Injection
                                    2: CRIME
                                    3: DROWN
                                    4: No Fallback SCSV Support
                                    5: No Forward Secrecy Support
                                    6: Heartbleed
                                    7: Insecure Renegotiation
                                    8: RC4 Support
                                    9: Session Ticket Support
                                    10: Sweet32
                             If this argument isn't specified all tests will be ran
-fc --fix-conf               Fix the /etc/ssl/openssl.cnf file to allow the use of older TLS protocols (TLSv1 and TLSv1.1) 
-st --sudo-tty               Use the terminal prompt to enter the sudo password
-ss --sudo-stdin             Use the stdin of the script to enter the sudo password
-ns --nmap-scan              Use nmap to scan the server version
-nd --nmap-discover          Use nmap to discover web server ports
-w  --worst                  Create a main connection on the worst available protocol version
-l  --logging                Enable logging   
-d  --debug                  Output debug information
-v  --version                Show script version and exit
-h  --help                   Show this help message and exit
```

### -fc argument

The `-fc` argument may rewrite the file located at `/etc/ssl/openssl.cnf` that is why a backup file is created with this
format `{old_file}.backup_{unix_time}` in the same folder as the config file

## Usage examples

```
$ SSLTest.py -u https://example.com -t 1 2 -cs
```

## Version History

* Full changelog [here](/CHANGELOG.md)
* [0.0.3](https://github.com/SamoKopecky/SSLTest/releases/tag/v0.0.3)
* [0.0.2](https://github.com/SamoKopecky/SSLTest/releases/tag/v0.0.2)
* [0.0.1](https://github.com/SamoKopecky/SSLTest/releases/tag/v0.0.1)

## Licence

Copyright (c) 2020 HACKER Consulting s.r.o.

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
License as published by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not,
see <https://www.gnu.org/licenses/>.
