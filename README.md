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

- libpcap
- libnet
- Linux (uses netlink for host information gathering)
- Root privileges or CAP_NET_RAW capability
- Build tools: gcc/clang, make, pkg-config

## Building

```bash
# Install dependencies (Debian/Ubuntu)
sudo apt-get install build-essential pkg-config libpcap-dev libnet1-dev

# Build
./build.sh
```

## Build Status

[![Build and Update Release](https://github.com/zimma/ndpresponder-c/actions/workflows/main.yml/badge.svg)](https://github.com/zimma/ndpresponder-c/actions/workflows/main.yml)

### Latest Release
[![Latest Release](https://img.shields.io/github/v/release/zimma/ndpresponder-c)](https://github.com/zimma/ndpresponder-c/releases/latest)
[![GitHub Release Date](https://img.shields.io/github/release-date/zimma/ndpresponder-c)](https://github.com/zimma/ndpresponder-c/releases/latest)
[![GitHub all releases](https://img.shields.io/github/downloads/zimma/ndpresponder-c/total)](https://github.com/zimma/ndpresponder-c/releases)

### Repository Stats
[![GitHub issues](https://img.shields.io/github/issues/zimma/ndpresponder-c)](https://github.com/zimma/ndpresponder-c/issues)
[![GitHub license](https://img.shields.io/github/license/zimma/ndpresponder-c)](https://github.com/zimma/ndpresponder-c/blob/main/LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/zimma/ndpresponder-c)](https://github.com/zimma/ndpresponder-c/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/zimma/ndpresponder-c)](https://github.com/zimma/ndpresponder-c/network/members)

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
```

## Implementation Details

This implementation uses:
- libpcap for packet capture
- libnet for packet creation
- netlink for host information gathering
- system commands to interface with Docker

The implementation follows the original Go program's architecture but is adapted for C.
