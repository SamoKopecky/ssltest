```
 ____            _                        _____           _
|  _ \ ___ _ __ | |_ ___ _ __ ___ _ __   |_   _|__   ___ | |___
| |_) / _ \ '_ \| __/ _ \ '__/ _ \ '_ \    | |/ _ \ / _ \| / __|
|  __/  __/ | | | ||  __/ | |  __/ |_) |   | | (_) | (_) | \__ \
|_|   \___|_| |_|\__\___|_|  \___| .__/    |_|\___/ \___/|_|___/
                                 |_|
```

# ssltest

A Python script that scans web servers cryptographic parameters and vulnerabilities. All available Vulnerability tests
can be found in the `help` output of the script or in the [options](#Options) section.

## Main features

Scan or test:

- Supported SSL/TLS protocols
- Detailed information about the certificate
- Detailed information about the cipher suite the connection was made with
- Web server software used by the server
- Chosen vulnerability tests
- Supported cipher suites for all SSL/TLS protocols

## Dependencies

Nmap is required for some functions of the script, install on debian-like distros with:

```shell
$ sudo apt-get install -y nmap
```

## Installation

```shell
$ pip install ssltest
```

## Installation (ptmanager)

```shell
$ sudo ptmanager -ut ssltest
```

## Options

```
   -u    --url            <url>       Url to scan, required option
   -p    --port           <port ...>  Port or ports (separate with spaces) to scan on (default: 443)
   -j    --json           <file>      Change output to json format, if a file name is specified output is written to the given file
   -t    --test           <num ...>   Run specified vulnerability tests (numbers) separated with spaces, if unspecified all tests are ran
     0   No tests                     Dont run any tests
     1   BREACH                       Test for https encoding methods
     2   CCS Injection                Test for Change Cipher Spec injection
     3   CRIME                        Test for ssl/tls encoding methods
     4   DROWN                        Test for rsa key exchange suites with ssl2 support
     5   Fallback SCSV                Test if fallback Signaling Cipher Suite Value is available
     6   Foward Secrecy               Test for forward secrecy cipher suites
     7   FREAK                        Test for RSA + EXPORT cipher suites
     8   HSTS                         Test for HTTP Strict Transport Security support
     9   Heartbleed                   Test for Heartbleed vulnerability
     10  Renegotiation                Test for insecure renegotiation (secure renegotiation extension)
     11  LOGJAM                       Test for DH + EXPORT cipher suites
     12  RC4 Support                  Test for RC4 cipher suites
     13  Session Ticket               Test for session ticket support
     14  SWEET32                      Test support for 64-bit key length encryption
   -to   --timeout        <dur>       Set a duration for the timeout of connections in seconds
   -sc   --short-cert                 Limit alternative names to first 5
   -cs   --cipher-suites              Scan all supported cipher suites by the server
   -fc   --fix-conf                   Fix the /etc/ssl/openssl.cnf file to allow the use of older TLS protocols (TLSv1 and TLSv1.1), requires root privileges (see -st and -ss options)
   -st   --sudo-tty                   Use the terminal prompt to enter the sudo password
   -ss   --sudo-stdin                 Use the stdin of the script to enter the sudo password
   -ns   --nmap-scan                  Use nmap to scan the server version
   -nd   --nmap-discover              Use nmap to discover web server ports, requires root privileges, (see -st and -ss options)
   -w    --worst                      Create a main connection on the worst available protocol version, otherwise servers preferred protocol version is chosen
   -l    --logging                    Enable logging
   -d    --debug                      Log debug information
   -v    --version                    Show script version and exit
   -h    --help                       Show this help message and exit
```

### -fc argument

The `-fc` argument may rewrite the file located at `/etc/ssl/openssl.cnf` that is why a backup file is created with this
format `{old_file}.backup_{unix_time}` in the same folder as the config file

## Contributing
- Check the [CONTRIBUTING.MD](CONTRIBUTING.md) file
- Development board can be see [here](https://trello.com/b/7XxY6gFy/ssltest)

## Usage examples

```
$ ./ssltest.py -u https://example.com -t 1 2 -cs
```

## Version History

* Full changelog [here](/CHANGELOG.md)
* [0.1.1](https://github.com/SamoKopecky/ssltest/releases/tag/v0.1.1)
* [0.1.0](https://github.com/SamoKopecky/ssltest/releases/tag/v0.1.0)
* [0.0.3](https://github.com/SamoKopecky/ssltest/releases/tag/v0.0.3)
* [0.0.2](https://github.com/SamoKopecky/ssltest/releases/tag/v0.0.2)
* [0.0.1](https://github.com/SamoKopecky/ssltest/releases/tag/v0.0.1)

## Licence

Copyright (c) 2020 HACKER Consulting s.r.o.

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
License as published by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not,
see <https://www.gnu.org/licenses/>.
