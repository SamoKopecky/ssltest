# Dependencies

- to install required python packages use `pip3 install -r requirements.txt` command which installs:
    - [cryptography](https://pypi.org/project/cryptography/)
    - [pyopenssl](https://pypi.org/project/pyOpenSSL/)
    - [python3-nmap](https://pypi.org/project/python3-nmap/)
    - [requests](https://pypi.org/project/requests/)
    - [urllib3](https://pypi.org/project/urllib3/)
    - [Flask](https://pypi.org/project/Flask/)
    - [flask-restful](https://pypi.org/project/Flask-RESTful/)
- nmap is required to for some functions, install with `apt install -y nmap`

# How to run

## Run the standalone script

- run the main file `tlstest.py` with option `-u` to enter the url.
- use `-h` or `--help` for more help.
- example: `./tlstest.py -u vutbr.cz -p 443`

## Deploy the web server

- to start the server app with the rest api server run the `start.sh` script

## Deploy the web server with docker

- to deploy on docker have docker engine ([guide here](https://docs.docker.com/engine/install/)) and docker
  compose ([guide here](https://docs.docker.com/compose/install/)) installed
- to deploy the docker run `docker-compose -up -d` command in the root project directory

https://www.overleaf.com/read/ggrmdgqqcwvq
