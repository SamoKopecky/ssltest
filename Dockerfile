FROM python:3

WORKDIR /usr/src/app
SHELL ["/bin/bash", "-c"]
RUN rm /usr/bin/python3 && \
ln -s /usr/local/bin/python3 /usr/bin/python3

COPY . ./
RUN pip3 install --no-cache-dir -r requirements.txt
RUN apt-get update && \
apt-get install -y nmap

EXPOSE 5001
EXPOSE 5000

CMD ["./start.sh", "-d", "-c"]
