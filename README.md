# NDP Responder (C Implementation)

This is a C implementation of an IPv6 Neighbor Discovery Protocol responder. It's a reimplementation of [yoursunny/ndpresponder](https://github.com/yoursunny/ndpresponder) which was originally written in Go.

## Features

- Responds to ICMPv6 neighbor solicitations for configured IPv6 subnets
- Monitors Docker containers and automatically responds for their IPv6 addresses
- Sends gratuitous neighbor advertisements for new Docker container IPs
- Configurable via command-line arguments

## Improvements Over Original

- Added extra functionality while maintaining core features
- Significantly reduced memory usage (from ~75MB to ~5MB)
- Eliminated bloat for a more efficient implementation
- Native C implementation for better performance

## Requirements

- libpcap, libnet1
- Linux (uses netlink for host information gathering)
- Root privileges or CAP_NET_RAW capability
- Build tools: gcc/clang, make, pkg-config

```bash
# Install to run (Debian/Ubuntu)
sudo apt-get install libnet1
```

## Building

```bash
# Install dependencies (Debian/Ubuntu)
sudo apt-get install build-essential pkg-config libpcap-dev libnet1-dev

# Build
./build.sh
```

## Running

This program requires root privileges or the CAP_NET_RAW capability to capture and send network packets.

```bash
# Run as root
sudo ./ndpresponder -i eth0 -n 2001:db8:1::/64

# Or set the capability and run as non-root
sudo setcap cap_net_raw+ep ./ndpresponder
./ndpresponder -i eth0 -n 2001:db8:1::/64
```

## Usage

```
Usage: ./ndpresponder -i INTERFACE [OPTIONS]
IPv6 Neighbor Discovery Protocol Responder

Options:
  -i, --interface INTERFACE  Uplink network interface
  -n, --subnet SUBNET        Static target subnet (IPv6/mask)
  -N, --docker-network NAME  Docker network name
  -p, --proactive            Proactively announce IPs at startup
  -v, --verbose              Enable verbose output
  -c, --config FILE          Path to configuration file
  -h, --help                 Show this help message
```

## Examples

```bash
# Respond for a static subnet
./ndpresponder -i eth0 -n 2001:db8:1::/64

# Respond for Docker containers
./ndpresponder -i eth0 -N my_docker_network

# Respond for both static subnets and Docker containers
./ndpresponder -i eth0 -n 2001:db8:1::/64 -N my_docker_network

# Use a configuration file
./ndpresponder -c /path/to/config/file

# Enable verbose logging
./ndpresponder -i eth0 -n 2001:db8:1::/64 -v

# Proactively announce IPs at startup with verbose output
./ndpresponder -i eth0 -n 2001:db8:1::/64 -p -v
```

## Implementation Details

This implementation uses:
- libpcap for packet capture
- libnet for packet creation
- netlink for host information gathering
- system commands to interface with Docker

The implementation follows the original Go program's architecture but is adapted for C.
