#!/bin/sh
# check if the script was executed with sudo
OUTPUT=$(id -u)
if [ $OUTPUT -gt 0 ]
then
  echo "please run the script as superuser"
  exit 1
fi

# starting server or client
if [ $# -gt 0 ]
then
  if [ $1 = "client" ]
  then
    # update system and install ffmpeg
    apt update
    apt install -y ffmpeg
    # install wiringPi
    apt install wiringpi

    # download go version
    wget https://golang.org/dl/go1.16.6.linux-armv6l.tar.gz
    # unpack go archive to /usr/local
    tar -xf go1.16.6.linux-armv6l.tar.gz -C /usr/local/
    # create symlink for go binary
    ln -s /usr/local/go/bin/go /bin/go
    #3
    echo "successfully installed all requirements..."
    echo "Starting client..."
    go run ./client/ "${@:2}"
  fi
  if [ $1 = "server" ]
  then
    echo "Starting server..."
    go run ./server/server.go "${@:2}"
  fi
fi
