# Simple SOCKS5 proxy server in Go

I was building an isolated network environment for testing, and I needed a simply and quick way to allow the machines in the isolated network to access the Internet. So I wrote this simple SOCKS5 proxy server in Go.

I use it by connecting a computer (usually my laptop) to both the isolated network using a wired connection and the Internet using Wi-Fi. Then I run this proxy server on that computer, and configure the machines in the isolated network to use it as their SOCKS5 proxy. This way, they can access the Internet through that computer.

## Usage

> I've only tested this on Linux, but it should work on other platforms as well.

I usually connect my laptop to the isolated network using a wired connection, and to the Internet using Wi-Fi. So I have two network interfaces: `eth0` for the wired connection, and `wlan0` for the Wi-Fi connection.

### Configure routing routes

You need to tell your computer to route the traffic from the isolated network to the Internet through the Wi-Fi interface. You can do this by adding a routing rule.

First examine the routing table to find out the default gateway for the Wi-Fi interface:

```bash
$ ip route

default via 192.168.1.1 dev wlp2s0 proto dhcp src 192.168.1.9 metric 600
default via 10.10.0.0 dev eth0 proto dhcp src 10.10.0.240 metric 600
```

You need to add a routing rule to route the traffic from the isolated network (10.10.0.0/24) to the Internet through the Wi-Fi interface. You can do this by running the following command:

```bash
sudo ip route del default dev eth0 
```

### Run the proxy server

You can specify the listening address, authentication credentials, and allowed CIDR blocks when running the proxy server. For example:

#### With username and password authentication:

```bash
go run . \
  -listen 192.168.131.169:1080 \
  -user ts -pass ts-pass \
  -allow-cidr 0.0.0.0/0,::/0 \
  -deny-private=false
```

#### No auth:

```bash
go run . \
  -listen 120.40.0.0:1080 \
  -allow-cidr 0.0.0.0/0,::/0 \
  -deny-private=false
```