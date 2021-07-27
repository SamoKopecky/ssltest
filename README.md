# Overview

- A standalone script that can be run in a console
- File `resources/security_levels.json` can be edited to change the parameter rating values

# Run the script

- Run the main file `ssltest.py` with option `-u` to enter the url.
- Use `-h` or `--help` for more help.
- Example: `./ssltest.py -u vutbr.cz`

## Prepare hosting OS environment

- If you are going to run the script these dependencies are required
- To install required python packages use `pip3 install -r requirements.txt` command which installs:
    - [cryptography](https://pypi.org/project/cryptography/)
    - [pyopenssl](https://pypi.org/project/pyOpenSSL/)
    - [python3-nmap](https://pypi.org/project/python3-nmap/)
    - [requests](https://pypi.org/project/requests/)
    - [urllib3](https://pypi.org/project/urllib3/)
    - [Flask](https://pypi.org/project/Flask/)
    - [flask-restful](https://pypi.org/project/Flask-RESTful/)
- Nmap is required to for some functions, install with `apt install -y nmap`
- To run the tool script refer to the section at the start

## Supported vulnerability tests

- Heartbleed
- CCS Injection
- Insecure renegotiation
- ZombiePOODLE/GOLDENDOODLE
- Session ticker support
- CRIME
- RC4 Support