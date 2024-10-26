#!/bin/bash

args="${*:1}"
gcc -o /tmp/udp-my-ip \
 server.c \
 $args
