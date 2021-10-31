# README for picamera
picamera is an implementation of a secure camera based on an inertial hardware security module.

## Repository Overview
This repository contains a reference implementation of a client and a server. The implementation is made for an raspberry pi 4 with a raspberry pi camera module attached to it.

## Client Installation
1. enable the raspberry pi camera interface in the system settings via `sudo raspi-config`
2. run `sudo /bin/bash ./install.sh client`

The video length can be changed by editing the VIDEO_LENGTH constant in the client.go file. 
The server URL can be changed by editing the SERVER_URL constant in the client.go file

Note: the SSL certificate of the server must be trusted by the raspbery pi since request are made with SSL/TLS.



## Server Installation 

Run go server.go —help for a list of available options. If no option for the certificate and private key is set the programm will use cert.pem and key.pem in the current working directory.

To start the server run `sudo /bin/bash ./install.sh server %additionalparameters%` or `go run server.go %additionalparameters%`

## Example video


## Warning
Note this repostitory is just a proof of concept and is not for productional use.
