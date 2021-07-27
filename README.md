# Overview

- This repository contains:
    - The standalone script that can be run in a console
    - Web server app that allows to use the script with a GUI (if hosted locally on this [url](http://localhost:5000))
- File `resources/security_levels.json` can be edited to change the parameter rating values

# Run the standalone script

- Run the main file `ssltest.py` with option `-u` to enter the url.
- Use `-h` or `--help` for more help.
- Example: `./ssltest.py -u vutbr.cz`

# Prepare the environment

- The required dependencies can be installed either on the hosting OS or by creating a docker container.

## Prepare hosting OS environment

- If you are going to run the script, or the web app on the hosting OS these dependencies are required
- To install required python packages use `pip3 install -r requirements.txt` command which installs:
    - [cryptography](https://pypi.org/project/cryptography/)
    - [pyopenssl](https://pypi.org/project/pyOpenSSL/)
    - [python3-nmap](https://pypi.org/project/python3-nmap/)
    - [requests](https://pypi.org/project/requests/)
    - [urllib3](https://pypi.org/project/urllib3/)
    - [Flask](https://pypi.org/project/Flask/)
    - [flask-restful](https://pypi.org/project/Flask-RESTful/)
- Nmap is required to for some functions, install with `apt install -y nmap`
- To start the server app with the rest api server run the `start.sh` script or `script.sh -h` for more information
- To run the tool script refer to the section at the start

## Create environment using docker

- To create the environment docker engine ([guide here](https://docs.docker.com/engine/install/)) and docker
  compose ([guide here](https://docs.docker.com/compose/install/)) need to be installed.
- Create the docker container with this command `docker-compose up -d` ran in the root project directory
- The web app will be automatically deployed, and the environment with required dependencies can be accessed via this
  command:
  `docker exec -it bp_flask_server /bin/bash`
- The standalone script can be then ran inside the created environment, refer to the section at the begging to see how
  to run the script

