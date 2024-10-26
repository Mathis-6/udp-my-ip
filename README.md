# udp-my-ip

A lightweight C program that receive packets and respond with the sender's IP address

# Getting started

You will need gcc to be installed to compile the project

```shell
git clone https://github.com/Mathis-6/udp-my-ip.git
cd udp-my-ip
./build.sh
```

If the build is successful, you will find the binary in /tmp

You can the move it to another persistent directory and create a service

# Securing it

As this project uses UDP, it will possibly be abused by some bad people

To prevent that, let's create a restrictive firewall rule with nftables. It only allows packet of 500 bytes to pass

```shell
nft add rule ip filter input udp dport 1634 meta length != 528 drop
```

# Creating a service

```shell
nano /etc/systemd/system/udp-my-ip.service
```

Enter the following text

```shell
[Unit]
Description=UDP server to return the client's IP address
After=multi-user.target

[Service]
Type=simple
Restart=always
ExecStart=/opt/udp-my-ip --listen-port 1634

[Install]
WantedBy=multi-user.target
```

Don't forget to change the binary's path and port if needed.
