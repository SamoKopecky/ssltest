#!/bin/bash


DOCKER=0
while getopts ":hcd" arg; do
  case ${arg} in
    h)
      echo "usage: use -h for more information"
      echo
      echo "This script runs the essential python files to deploy"
      echo "a web server for tlstest tool. Script kills all the created"
      echo "processes when user enters anything into the script."
      echo "Termination of child processes may not work if script"
      echo "is ran as root!"
      echo
      echo "optional arguments:
        -h  displays this message
        -c  allow the use of older versions of TLS protocol
            (TLSv1 and TLSv1.1) in order to scan a server which
            still run on these versions.
            !WARNING!: this may rewrite the contents of a
            configuration file located at /etc/ssl/openssl.cnf
            backup is recommended, root permission required
        -d  run the script for docker, only use if running in docker"
      exit 0;;
    c)
      python3 fix_openssl_config.py;;
    d)
      DOCKER=1;;
    ?)
      echo "usage: use -h for more information"
      exit 1;;
    esac
done

# Trap exit signals to termite child processes
trap "trap - SIGTERM && kill -- -$$" SIGINT SIGTERM EXIT

# Change to the directory of the script so that other
# scripts can be ran
cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null 

LOGDIR="./logs"
RESTAPI_LOGFILE="${LOGDIR}/restapi.log"
SERVERAPP_LOGFILE="${LOGDIR}/server_app.log"

# Check if directory already exists
if ! [ -d "${LOGDIR}" ]; then
  mkdir $LOGDIR
fi

echo "Starting restapi and the server app in background ..."
echo "Storing logs for restapi in ${RESTAPI_LOGFILE} ..."
echo "Storing logs for server app in ${SERVERAPP_LOGFILE} ..."

# Redirect stdout and stderr to a log file
python3 ./restapi.py >$RESTAPI_LOGFILE 2>&1 &
if [ 1 -eq $DOCKER ]; then
  python3 ./server_app/server.py >$SERVERAPP_LOGFILE 2>&1
else
  python3 ./server_app/server.py >$SERVERAPP_LOGFILE 2>&1 &
  echo "To terminate server processes press enter"
  read
fi


