# Features

The script can handle scanning a single url (`-u/--url`) per one run. If more ports are specified with the `-p/--port` it will sequentially scan the provided ports.

Multiple vulnerability tests are available, see the [Vulnerabilities](vulnerabilities.md) file.

## Output format

The output format of the script is a json object that is by default formatted using a custom formatter into the `stdout` of the run environment. If a formatted output is not desired it is possible to purly output the json object by either saving it to a file or outputting it to the `stdout` file descriptor (option `-j/--json`).

## Cipher suite scanning

Using the option `-cs/--cipher-suites` it is possible to scan **all** the possible cipher suites the peer is going to accept during the [handshake procedure](https://www.cloudflare.com/learning/ssl/what-happens-in-a-tls-handshake). If the peer that is being scanned rejects too many connections and the scan fails, an edit would be needed in the `network_profiles.json` configuration file (see the [configuration section](configuration.md#scanning-speed)).

## Fixing `openssl.cnf`

The `-fc/--fix-conf` option can be used to allow the use of older TLS protocols (`TLSv1.0` and `TLSv1.1`), if not supported by your installed `openssl` library. It may rewrite the file located at `/etc/ssl/openssl.cnf` that is why a backup file is created with this format `{old_file}.backup_{unix_time}` in the same folder as the config file.

## Other notable features
Other notable features that are pretty self-explanatory are:
- `-cc/--cert-chain` -- Certificate chain scanning not just the endpoint certificate.
- `-sn/--short-names` -- Shorten alternative names from certificates.
- `-w/--worst` -- Choosing the worst available protocol version for connection
- `-nd/--nmap-discover` -- Host discovery using nmap (not very reliable right now)
- `-ns/--nmap-scan` -- Scan web server version using nmap
- `-i/--info`/`-d/--debug` -- Info/debug information
