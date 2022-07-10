```
 ____            _                        _____           _
|  _ \ ___ _ __ | |_ ___ _ __ ___ _ __   |_   _|__   ___ | |___
| |_) / _ \ '_ \| __/ _ \ '__/ _ \ '_ \    | |/ _ \ / _ \| / __|
|  __/  __/ | | | ||  __/ | |  __/ |_) |   | | (_) | (_) | \__ \
|_|   \___|_| |_|\__\___|_|  \___| .__/    |_|\___/ \___/|_|___/
                                 |_|
```

# ssltest

Scan web servers cryptographic parameters and chosen vulnerabilities.

TODO: add more badges
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

## Documentation
Documentation is available at TODO

## Main features

Scan or test:

- Supported SSL/TLS protocols
- Detailed information about the certificate
- Detailed information about the cipher suite the connection was made with
- Web server software used by the server
- Chosen vulnerability tests
- Supported cipher suites for all SSL/TLS protocols

## Installation

To install from [pypi](https://pypi.org/project/ssltest/) run:
```shell
pip install ssltest
```

To install straight from source run:
```shell
git clone git@github.com:SamoKopecky/ssltest.git && \
cd ssltest && \
pip install .
```

Nmap is required for some functions of the script (`--ns/--nmap-scan` and `--nd/--nmap-discover`), install on debian-like distros with:

```shell
apt-get install -y nmap
```

## Contributing
Check the [CONTRIBUTING.MD](CONTRIBUTING.md) file

## Usage examples
TODO: sync with documentation

```
$ ssltest -u https://example.com -t 1 2 -cs
```

## Licence

Copyright (c) 2022 HACKER Consulting s.r.o.

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
License as published by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not,
see <https://www.gnu.org/licenses/>.
