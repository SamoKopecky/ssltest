FROM python:3

WORKDIR /usr/src/app

COPY . ./
RUN pip install --no-cache-dir -r requirements.txt
RUN apt-get update && \
apt-get install -y nmap

EXPOSE 5001
EXPOSE 5000

RUN ./fix_openssl_config.py
RUN python3 ./restapi.py &
CMD ["python3", "./server_app/server.py"]
