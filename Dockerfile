FROM python:3

WORKDIR /usr/src/app

COPY . ./
RUN pip install --no-cache-dir -r requirements.txt
RUN apt-get update && \
apt-get install -y nmap

EXPOSE 5001
EXPOSE 5000

CMD ["./start.sh"]
