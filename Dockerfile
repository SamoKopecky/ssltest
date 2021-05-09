FROM python:3

WORKDIR /usr/src/app

COPY . ./
RUN pip install --no-cache-dir -r requirements.txt
RUN python3 restapi &

EXPOSE 5001
EXPOSE 5000

CMD ["./run.sh"]
