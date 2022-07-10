% ssltest documentation master file, created by
% sphinx-quickstart on Sat Jul 9 09:56:52 2022.
% You can adapt this file completely to your liking, but it should at least
% contain the root `toctree` directive.

# ssltest

Welcome to the main documentation for the `ssltest` scanning tool. This tool is also available at [pypi](https://pypi.org/project/ssltest/).

## Features

Scan web servers cryptographic parameters and chosen vulnerabilities.

Available features can be found on the [features](features.md) page.

All available Vulnerability tests can be found in the `-h/--help` output of the script, or in the [vulnerability tests](vulnerabilities.md) page on this documentation.

[//]: # (- {ref}`search`)

## Installation

To install from [pypi](https://pypi.org/project/ssltest/) run:
```shell
pip install ssltest
```

To install a more up-to-date version run:
```shell
git clone git@github.com:SamoKopecky/ssltest.git && \
cd ssltest && \
pip install .
```

Nmap is required for some functions of the script (`--ns/--nmap-scan` and `--nd/--nmap-discover`), install on debian-like distros with:

```shell
apt-get install -y nmap
```

## Usage examples

TODO: add more usages

```
$ ssltest -u vut.cz -t 1 2 -cs
```

## Configuration files

Configuration files for the application are stored in `$HOME/.config/ssltest`. They can be edited to change the rules by which the application is rating the web server parameters.

- You need to run the application at least once in order to copy the files to the config folder.

```{toctree}
:maxdepth: 1
:hidden:

contributing
features
vulnerabilities
version-history
```
