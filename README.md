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
can be found in the `help` output of the script.

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

For the most up-to-date version clone the repository and install with:

```shell
$ pip install .
```

## Installation (ptmanager)

```shell
$ sudo ptmanager -ut ssltest
```

## Configuration files
Configuration files for the application are stored in `$HOME/.config/ssltest`. They can be edited to change the rules by
which the application is rating the web server parameters.
- You need to run the application at least once in order to copy the files to the config folder.

## -fc argument

The `-fc` argument may rewrite the file located at `/etc/ssl/openssl.cnf` that is why a backup file is created with this
format `{old_file}.backup_{unix_time}` in the same folder as the config file

## Contributing
- Check the [CONTRIBUTING.MD](CONTRIBUTING.md) file
- Development board can be see [here](https://trello.com/b/7XxY6gFy/ssltest)

## Usage examples

```
$ ssltest -u https://example.com -t 1 2 -cs
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
