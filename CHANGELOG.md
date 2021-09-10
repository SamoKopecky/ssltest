# Changelog

All notable changes to this project will be documented in this file.

# [0.0.1](https://github.com/SamoKopecky/SSLTest/releases/tag/v0.0.1) - Aug 10, 2021



### Added

- A forked repository from https://github.com/SamoKopecky/BP
- SSLv3 protocol support scanning, cipher suite and endpoint certificate scanning
- SSLv2 protocol support scanning, endpoint certificate scanning
- Fixed cipher suite while connecting on SSLv2 ([why](https://github.com/SamoKopecky/SSLTest/commit/7140c464696112cefb63862961f82adee043ca38))
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

# [0.0.2](https://github.com/SamoKopecky/SSLTest/compare/v0.0.1...v0.0.2) - Sep 7, 2021

### Added

- Certificate verification for SSLv3/SSLv2 using the [Mozilla CA Certificate list](https://wiki.mozilla.org/CA/Included_Certificates)
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

- TLS protocol version scanning using the native python [ssl](https://docs.python.org/3/library/ssl.html) library instead of [pyOpenSSL](https://www.pyopenssl.org/en/stable/), which fixed many bugs
- Script no longer needs to be run as root to run the OpenSSL config file fix
- SSLv2 cipher suite is now chosen at random ([why](https://github.com/SamoKopecky/SSLTest/commit/cbc230ddffbf07a900345533fbea823cdcc36de5))
- Chosen cipher suites for client hellos in vulnerability tests are generated using the python [ssl](https://docs.python.org/3/library/ssl.html) library to improve compatibility 
