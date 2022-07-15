% ssltest documentation master file, created by
% sphinx-quickstart on Sat Jul 9 09:56:52 2022.

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

```{toctree}
:maxdepth: 1
:hidden:

features
vulnerabilities
configuration
contributing
version-history
```
