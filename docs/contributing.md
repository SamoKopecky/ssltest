# Contributing

[fork]: https://github.com/SamoKopecky/ssltest/fork
[pr]: https://github.com/SamoKopecky/ssltest/compare

All contributions are welcome!

Please note that this project is released with a [Contributor Code of Conduct](https://example.com). By participating in this project you agree to abide by its terms.

You can visit the development board [here](https://trello.com/b/7XxY6gFy/ssltest).

## Issues

We'd love you to open issues, if they're relevant to this repository: feature requests, bug reports, etc. are all welcome.

In particular, if you have a large PR you want to send our way, it may make sense to open an issue to discuss it with the maintainers first.

## Submitting a pull request

1. [Fork][fork] and clone the repository
2. Make your changes
3. Push to your fork and [submit a pull request][pr]
4. Pat your self on the back and wait for your pull request to be reviewed and merged.

Here are a few things you can do that will increase the likelihood of your pull request being accepted:

- Install and use [pre-commit](https://pre-commit.com/) to follow the same code style and conventions.
- Keep your change as focused as possible. If there are multiple changes you would like to make that are not dependent
  upon each other, consider submitting them as separate pull requests.
- Write a [good commit message](http://tbaggery.com/2008/04/19/a-note-about-git-commit-messages.html), please
  use [conventional commits](https://www.conventionalcommits.org/en/v1.0.0/)

Work in Progress pull request are also welcome to get feedback early on, or if there is something blocked you. Please open such pull requests as *Draft*.

## Development setup

For a development setup follow these steps:

1. Create a virtual environment:

```shell
python3 -m venv path/to/myvenv
```

2. Active the newly created virtual environment:

```shell
source path/to/myvenv/bin/activate
```

3. Install `ssltest` package, the `-e` option allows for hot reload of your code

```shell
pip install -e .
```

4. Nmap is required for some functions of the script (`--ns/--nmap-scan` and `--nd/--nmap-discover`), install on debian-like distros with:

```shell
apt-get install -y nmap
```

5. To get out of your `venv` use:

```shell
deactivate
```

## Contribute a new vulnerability test

In order to create a **vulnerability test** some conditions have to be met:

1. The test class has to inherit from the `VulnerablityTest` class and implement required abstract methods and call the
   super constructor (`super().__init__`).
2. The `test` method has to be implemented and has to return either a `bool` or a `tuple(bool, str)`. The string in the
   tuple return variant is a note to the test result and will be displayed in the tool output.
3. The variable `valid_protocols` has to be set to a list of SSL/TLS protocols you want the test to run on.
4. Static variables `name`, `short_name` and `description` have to be defined.
6. Test class has to be in `ssltest/scan_vulnerabilities/tests`.
5. The doc of the file that hosts the test class has to start with this string `Vulnerability test for`.

Template vulnerability test class can be found in `ssltest/scan_vulnerabilities/tests/TestTemplate.py`

### Other useful tools for implementing tests

- The variable `test_once` can be set to `False` to run the test on multiple protocol versions in parallel. Protocols are chosen based on the intersection of `valid_protocols` and `supported_protocols` lists.
- If the variable `test_once` is set to `True` the test will be run on the first available protocol version from the `valid_protocols` lists.
- The method `run_once()` can be implemented in case the `test_once` variable is set to `False` to run some code before the parallel run of tests on multiple protocols (e.g. `Drown`).
- The `ClientHello` class can be used to create the initial client hello message, where every client hello field can be customized such as cipher suites or TLS extensions.
- The `SafeSocket` is the recommended way to send data, check other tests for example on how to use it.
- The `CipherSuiteTest` class can be used to create a simplified vulnerability test where it is filtering cipher suites based on a regex string and checks if the server supports these filtered cipher suites. Set this regex string with the `self.filter_regex` variable. Check the `Freak` class for an example.


## Updating `CHANGELOG.md`
TODO

## Release process
TODO
