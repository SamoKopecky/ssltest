#!/bin/bash

# Trap exit signals to termite child processes
trap "trap - SIGTERM && kill -- -$$" SIGINT SIGTERM EXIT

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
python3 ./server_app/server.py >$SERVERAPP_LOGFILE 2>&1 &

echo "To terminate server processes press enter"
read