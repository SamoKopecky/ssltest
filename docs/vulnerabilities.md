# Vulnerabilities

Available vulnerability tests in no specific order include:
- **BREACH** -- Test for https encoding methods
- **CCS Injection** -- Test for Change Cipher Spec injection
- **CRIME** -- Test for ssl/tls encoding methods
- **DROWN** -- Test for rsa key exchange suites with ssl2 support
- **Fallback SCSV** -- Test if fallback Signaling Cipher Suite Value is available
- **Forward Secrecy** -- Test for forward secrecy cipher suites
- **FREAK** -- Test for RSA + EXPORT cipher suites
- **HSTS** -- Test for HTTP Strict Transport Security support
- **Heartbleed** -- Test for Heartbleed vulnerability
- **Renegotiation** -- Test for insecure renegotiation (secure renegotiation extension)
- **LOGJAM** -- Test for DH + EXPORT cipher suites
- **RC4 Support** -- Test for RC4 cipher suites
- **Session Ticket** -- Test for session ticket support
- **SWEET32** -- Test support for 64-bit key length encryption

## Creating new tests

- Check the [contributing](contributing.md#contribute-a-new-vulnerability-test) file for a guide on how to contribute by creating new tests.
