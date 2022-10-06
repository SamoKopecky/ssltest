```
 ____            _                        _____           _
|  _ \ ___ _ __ | |_ ___ _ __ ___ _ __   |_   _|__   ___ | |___
| |_) / _ \ '_ \| __/ _ \ '__/ _ \ '_ \    | |/ _ \ / _ \| / __|
|  __/  __/ | | | ||  __/ | |  __/ |_) |   | | (_) | (_) | \__ \
|_|   \___|_| |_|\__\___|_|  \___| .__/    |_|\___/ \___/|_|___/
                                 |_|
```

<p align="center">
    <a href="https://pypi.org/project/ssltest/" alt="pypi">
        <img src="https://img.shields.io/pypi/v/ssltest" /></a>
    <a href="https://github.com/SamoKopecky/ssltest/blob/master/LICENSE" alt="License">
        <img src="https://img.shields.io/github/license/samokopecky/ssltest?color=blue" /></a>
    <a href='https://ssltest.readthedocs.io/en/latest/?badge=latest'>
        <img src='https://readthedocs.org/projects/ssltest/badge/?version=latest' alt='Documentation Status' />
    <a href="https://github.com/psf/black" alt="Code style: black">
        <img src="https://img.shields.io/badge/code%20style-black-000000.svg" /></a>
</a>
</p>

# ssltest

Scan web servers cryptographic parameters and chosen vulnerabilities.

## Documentation

Documentation is available [here](https://ssltest.readthedocs.io/en/latest/).

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

Basic scan with no vulnerability tests:

```shell
ssltest -u nmap.org -t 0
```

Scan all vulnerability tests and available cipher suites:

```shell
ssltest -u nmap.org -cs
```

Scan for `Heartbleed` vulnerability, scan the whole certificate chain and shorted alternative names in the output:

```shell
ssltest -u nmap.org -t 9 -cc -sn
```

Scan using custom config files in debug mode:

```shell
ssltest -u nmap.org -c ~/.config/custom_ssltest -d
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
