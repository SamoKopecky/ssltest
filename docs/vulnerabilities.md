# Vulnerabilities

You can run multiple tests in parallel by specifying the `-t/--test` option using test number separated by spaces. All tests are run if no test option is specified.

Available vulnerability tests in alphabetical order include:
1. **BREACH** -- Test for https encoding methods
2. **CCS Injection** -- Test for Change Cipher Spec injection
3. **CRIME** -- Test for ssl/tls encoding methods
4. **DROWN** -- Test for rsa key exchange suites with ssl2 support
5. **Fallback SCSV** -- Test if fallback Signaling Cipher Suite Value is available
6. **Forward Secrecy** -- Test for forward secrecy cipher suites
7. **FREAK** -- Test for RSA + EXPORT cipher suites
8. **HSTS** -- Test for HTTP Strict Transport Security support
9. **Heartbleed** -- Test for Heartbleed vulnerability
10. **Renegotiation** -- Test for insecure renegotiation (secure renegotiation extension)
11. **LOGJAM** -- Test for DH + EXPORT cipher suites
12. **RC4 Support** -- Test for RC4 cipher suites
13. **Session Ticket** -- Test for session ticket support
14. **SWEET32** -- Test support for 64-bit key length encryption

## Creating new tests

- Check the [contributing](contributing.md#contribute-a-new-vulnerability-test) file for a guide on how to contribute by creating new tests.
