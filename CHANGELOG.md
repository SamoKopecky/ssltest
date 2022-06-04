# Changelog

All notable changes to this project will be documented in this file.

# [0.1.1](https://github.com/SamoKopecky/SSLTest/compare/v0.1.0...v0.1.1) - Dec 22, 2021
### Added
- Vulnerability test for HSTS support, FREAK, LOGJAM, BREACH
- Symmetric algorithm mod category for EXPORT cipher suites
- Vulnerability tests can also return a string description of the test result
- Contributing information for implementing new vulnerability tests and Vulnerability test class template
- Requirement of `-st` or `-ss` option for `-nd` or `--nmap-discover` option since the reworked function now requires
root privileges

### Changed
- The format vulnerability tests are displayed in the `--help` or `-h` output
- Function of the `-nd` or `--nmap-discover` option

# [0.1.0](https://github.com/SamoKopecky/SSLTest/compare/v0.0.3...v0.1.0) - Oct 24, 2021

### Added
- Improved text output in console
- `-sc --short-cert` option to shorten alternative names output

### Changed
- Vulnerability tests no longer need to be hardcoded in a dictionary to run, they are automatically parsed
from the tests module

# [0.0.3](https://github.com/SamoKopecky/SSLTest/compare/v0.0.2...v0.0.3) - Oct 13, 2021

### Added

- `-t --timeout` option
- `-cs --cipher-suites` option to scan for cipher suite support
- Automatic Cipher suite support scanning for SSLv2 protocol version if chosen as the main protocol
- Support for symmetric encryption modification values like `EDE3` and `EXPORT40`
- Expansion of the `ciher_suites.json` file with protocol support for each cipher suite
    - This is used when creating cipher suites for client hellos in vulnerability tests, SSL protocol scanning and
      cipher suite scanning
- `DROWN`, `Sweet32` and `Forward secrecy support` vulnerability tests
- Split the `run.py` file into two logical sections for code readability
- Additional logging levels (`Warning`, `Error`) and improve the logging system
- Creation of backups when modifying the `/etc/ssl/openssl.cnf` file with `-fc` option
- Properer handling for servers with no HTTPS support

### Changed

- Instead of choosing the best protocol version, protocol is chosen by the server for TLS protocols, for SSL protocols
  the best SSL protocol is chosen
- Change `-i --info` option to `-l --logging`
- Add `-st -sudo--tty` and `-ss -sudo--stdin` options for entering the sudo password instead of automatic detection

# [0.0.2](https://github.com/SamoKopecky/SSLTest/compare/v0.0.1...v0.0.2) - Sep 7, 2021

### Added

- Certificate verification for SSLv3/SSLv2 using
  the [Mozilla CA Certificate list](https://wiki.mozilla.org/CA/Included_Certificates)
- Whole certificate chain scanning for SSLv3, not just the endpoint certificate
- More detailed logging for `-d` and `-i` options
- Choice to pipe in a sudo password via a pipe (`|`) to `stdin` for the purposes of running the OpenSSL config file fix
- Prompt to input the sudo password while running the tool for the purposes of running the OpenSSL config file fix
- `-w --worst` option to connect with the worst available protocol, otherwise the best option is chosen
- Reworked vulnerability testing system which includes:
    - Tests running on every valid protocol version to scan for vulnerabilities (still in parallel)
    - New vulnerabilities can be implemented easier than before
    - Improved logging
- Fallback SCSV support vulnerability

### Changed

- TLS protocol version scanning using the native python [ssl](https://docs.python.org/3/library/ssl.html) library
  instead of [pyOpenSSL](https://www.pyopenssl.org/en/stable/), which fixed many bugs
- Script no longer needs to be run as root to run the OpenSSL config file fix
- SSLv2 cipher suite is now chosen at
  random ([why](https://github.com/SamoKopecky/SSLTest/commit/cbc230ddffbf07a900345533fbea823cdcc36de5))
- Chosen cipher suites for client hellos in vulnerability tests are generated using the
  python [ssl](https://docs.python.org/3/library/ssl.html) library to improve compatibility

# [0.0.1](https://github.com/SamoKopecky/SSLTest/releases/tag/v0.0.1) - Aug 10, 2021

### Added

- A forked repository from https://github.com/SamoKopecky/BP
- SSLv3 protocol support scanning, cipher suite and endpoint certificate scanning
- SSLv2 protocol support scanning, endpoint certificate scanning
- Fixed cipher suite while connecting on
  SSLv2 ([why](https://github.com/SamoKopecky/SSLTest/commit/7140c464696112cefb63862961f82adee043ca38))
- Option `-t 0` for not running any tests, if no `-t` option is present all tests are ran
- Script integration with the `penterep tools` template
- `-v --version` option to show tool version
- [LICENSE](LICENSE) file

### Changed

- Rename the tool to SSLTest instead of TLSTest
- TLSv1 now appears everywhere in the program as TLSv1.0
- Change verbose (`-v`) option to debug (`-d`)

### Removed

- Removed the web server GUI/rest API functionality
