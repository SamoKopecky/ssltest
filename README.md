```
 ____            _                        _____           _     
|  _ \ ___ _ __ | |_ ___ _ __ ___ _ __   |_   _|__   ___ | |___ 
| |_) / _ \ '_ \| __/ _ \ '__/ _ \ '_ \    | |/ _ \ / _ \| / __|
|  __/  __/ | | | ||  __/ | |  __/ |_) |   | | (_) | (_) | \__ \
|_|   \___|_| |_|\__\___|_|  \___| .__/    |_|\___/ \___/|_|___/
                                 |_|
```

# SSLTest

Script that scans web servers cryptographic parameters and vulnerabilities



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
                                   2: Crime
                                   3: No Fallback SCSV Support
                                   4: Heartbleed
                                   5: Insecure Renegotiation
                                   6: RC4 Support
                                   7: Session Ticket Support
                                   8: DROWN
                                   9: Sweet32
                                   10: No Forward Secrecy Support
                             If this argument isn't specified all tests will be ran
-fc --fix-conf               Fix the /etc/ssl/openssl.cnf file to allow the use of older TLS protocols (TLSv1 and TLSv1.1) 
                             protocol versions of TLS protocol (TLSv1 and TLSv1.1)
-st --sudo-tty               Use the terminal prompt to enter the sudo password
-ss --sudo-stdin             Use the stdin of the script to enter the sudo password
-ns --nmap-scan              Use nmap to scan the server version
-nd --nmap-discover          Use nmap to discover web server ports
-w  --worst                  Create a main connection on the worst available protocol version
-i  --info                   Output some internal information about the script functions
-d  --debug                  Output debug information
-v  --version                Show script version and exit
-h  --help                   Show this help message and exit
```
### -fc argument
TODO

## Usage examples

```
$ SSLTest.py -u https://example.com -t 1 2
```

## Version History

* Full changelog [here](/CHANGELOG.md)
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
