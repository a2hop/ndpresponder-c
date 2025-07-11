# NDP Responder (C Implementation)

It's a C reimplementation of [yoursunny/ndpresponder](https://github.com/yoursunny/ndpresponder) which was originally written in Go.

## Features

- Responds to ICMPv6 neighbor solicitations for configured IPv6 subnets
- Supports excluded subnets that will not be responded to (using "nix" prefix)
- Monitors Docker containers and automatically responds for their IPv6 addresses
- Sends gratuitous neighbor advertisements for new Docker container IPs
- Configurable via command-line arguments or configuration file

## Improvements Over Original

- Significantly reduced memory usage (from ~75MB to ~5MB)
- Reduced binary size from 13.5MB to 34kB
- Added extra functionality while maintaining core features
- Eliminated bloat for a more efficient implementation
- Native C implementation for better performance
- Support for excluded subnets

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

## Configuration File

The configuration file supports the following directives:

- `link INTERFACE` - Set the network interface
- `net SUBNET` - Add a subnet to respond for (IPv6/prefix)
- `nix SUBNET` - Add an excluded subnet (will not respond for these IPs)
- `docker NETWORK` - Add a Docker network to monitor
- `proactive` - Enable proactive announcements at startup
- `verbose` - Enable verbose output

### Example Configuration

```
# Network interface to use
link bri1

# IPv6 subnets to respond for
net 2001:db8:1:2::100/120
net 2001:db8:3:4::abc/128
net fd00:1234:5678:9abc::42/128

# Excluded subnets (will not respond for these)
nix 2001:db8:5:7::def/112

# Docker networks to monitor (optional)
docker my_docker_network

# Enable proactive announcements at startup
proactive

# Enable verbose output
verbose
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

## Excluded Subnets

The "nix" prefix allows you to specify subnets that should be excluded from responses. This is useful when you want to respond for a large subnet but exclude certain ranges within it. Excluded subnets are checked first, so they take precedence over included subnets.

For example:
```
net 2001:db8::/32          # Respond for entire /32
nix 2001:db8:1::/48        # But exclude this /48 within it
```

