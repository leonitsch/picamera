#!/bin/sh
# check if the script was executed with sudo
OUTPUT=$(id -u)
if [ $OUTPUT -gt 0 ]
then
  echo "please run the script as superuser"
fi
# update system and install ffmpeg
apt-get update
apt-get install -y ffmpeg
# download go version
wget https://golang.org/dl/go1.16.6.linux-armv6l.tar.gz
# unpack go archive to /usr/local
tar -xfz go1.16.6.linux-armv6l.tar.gz -C /usr/local/
# create symlink for go binary
ln -s /usr/local/go/bin/go /bin/go
# 
echo "successfully installed all requirements..."

