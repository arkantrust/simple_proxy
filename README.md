# Simple SOCKS5 Proxy Server in Go

I was building an isolated network environment for testing and needed a simple, quick way to allow machines in the isolated network to access the Internet. So I wrote this simple SOCKS5 proxy server in Go.

I use it by connecting a computer (usually my laptop) to both the isolated network via a wired connection and the Internet via Wi-Fi. Then I run this proxy server on that computer and configure the machines in the isolated network to use it as their SOCKS5 proxy (so they can reach the Internet through it).

> [!NOTE]
> I've only tested this on Linux, but it should work on other platforms as well.

## Usage

### 1. Configure routing

You need to make sure your computer routes traffic from the isolated network out through the Wi-Fi interface, not back into the isolated network.

First, examine your routing table:

```bash
ip route
```

```
default via 192.168.1.1 dev wlp2s0 proto dhcp src 192.168.1.105 metric 600
10.10.0.0/24 dev enp3s0 proto kernel scope link src 10.10.0.240
```

In this example, `wlp2s0` is the Wi-Fi interface (with Internet access) and `enp3s0` is the wired interface connected to the isolated network. If there is a default route pointing to `enp3s0`, remove it:

```bash
sudo ip route del default dev enp3s0
```

### 2. Run the proxy server

Run the proxy server on the interface connected to the isolated network. You can configure the listening address, authentication credentials, and allowed CIDR blocks.

**With username/password authentication:**

```bash
go run . \
  -listen 10.10.0.240:1080 \
  -user myuser \
  -pass mypassword \
  -allow-cidr 0.0.0.0/0,::/0 \
  -deny-private=false
```

**Without authentication:**

```bash
go run . \
  -listen 10.10.0.240:1080 \
  -allow-cidr 0.0.0.0/0,::/0 \
  -deny-private=false
```

### 3. Configure clients

On each machine in the isolated network, set the SOCKS5 proxy to the address and port you configured above — for example, `10.10.0.240:1080`.
