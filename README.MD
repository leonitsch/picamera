# README for picamera
picamera is an implementation of a secure camera based on an inertial hardware security module.

## Repository Overview
This repository contains two reference implementations, one written in pure GO and one written in GO and C. Only the second one guarantees to be pretty secure, since the GO implementation does not contain any `memset_s` implementation for key zeroization.


## Installation
For installation run : `./install.sh server` or `./install.sh client`

To start the server: `cd server/` and run `go run .`
