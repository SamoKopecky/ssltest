# Prehľad

- Tento repozitár obsahuje:
    - Samostatný skript, ktorý je možné spustiť v konzoli
    - Aplikácia webového servera, ktorá umožňuje používať skript s GUI (ak je hostovaný lokálne na tejto [url](http: // localhost: 5000))

# Spustenie samostatného skriptu

- Spustenie hlavného súboru je možné z príkazom `tlstest.py` a z prepínačom `-u` po zadaní url web servera
- Prepínač `-h` alebo `--help` slúži na zobrazenie viacej informácií
- Príklad spustenia: `./tlstest.py -u vutbr.cz`

# Pripravenie prostredia

- Potrebné závislosti sa dajú nainštalovať buď na hostovaciom OS alebo cez vytvorenie docker kontajneru

## Príprava hostovacieho OS

- Pre spustenie skriptu alebo webovej aplikácie na hostovaciom OS, tieto závislosti sú potrebné
- Inštalácia potrebných python balíčkov je možná pomocou príkazu `pip3 install -r requirements.txt`, ktorý inštaluje:
    - [cryptography](https://pypi.org/project/cryptography/)
    - [pyopenssl](https://pypi.org/project/pyOpenSSL/)
    - [python3-nmap](https://pypi.org/project/python3-nmap/)
    - [requests](https://pypi.org/project/requests/)
    - [urllib3](https://pypi.org/project/urllib3/)
    - [Flask](https://pypi.org/project/Flask/)
    - [flask-restful](https://pypi.org/project/Flask-RESTful/)
- Program nmap je potrebný pre niektoré funkcie programu, inštalácia je možná pomocou príkazu `apt install -y nmap`
- Spustenie webovej aplikácie spolu s rest api je možné pomocou spustenia skriptu príkazom `start.sh` alebo príkazom `script.sh -h` pre zobrazenie viacej informácií
- Spustenie samostatného skriptu je popísane na začiatku

## Vytvorenie prostredia pomocou dockeru

- Pre vytvorenie prostredia je potrebné nainštalovať, docker engine ([návod](https://docs.docker.com/engine/install/)) a docker
  compose ([návod](https://docs.docker.com/compose/install/))
- Vytvorenie docker kontajneru je možné pomocou príkazu `docker-compose up -d` spustením v root zložke projektu
- Webová aplikácie bude automaticky spustená a prostredie s potrebnými závislostami je prístupné pomocou príkazu `docker exec -it bp_flask_server /bin/bash`
- Samostatný skript je možné spustiť vo vytvorenom prostredí, spustenie skriptu je popísane na začiatku

https://www.overleaf.com/read/ggrmdgqqcwvq

