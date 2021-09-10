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
                               1: Heartbleed
                               2: CCS injection
                               3: Insecure renegotiation
                               4: ZombiePOODLE/GOLDENDOOLDE
                               5: Session ticket support
                               6: CRIME
                               7: RC4 support
                             If this argument isn't specified all tests will be ran
-fc --fix-conf               Allow the use of older versions of TLS protocol (TLSv1 and TLSv1.1) 
                             in order to scan a server which still run on these versions. 
                             !WARNING!: this may rewrite the contents of a configuration file 
                             located at /etc/ssl/openssl.cnf. Password can be piped to stdin or
                             entered when prompted at the start of the script if no pipe is present
-ns --nmap-scan              Use nmap to scan the server version
-nd --nmap-discover          Use nmap to discover web server ports
-w  --worst                  Create a main connection on the worst available protocol version
-i  --info                   Output some internal information about the script functions
-d  --debug                  Output debug information
-v  --version                Show script version and exit
-h  --help                   Show this help message and exit
```

## Usage examples

```
$ SSLTest.py -u https://example.com -t 1 2
```

## Version History

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
