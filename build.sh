#!/bin/bash

set -e

CC=${CC:-gcc}
CFLAGS="-Wall -Werror -g -O2"
LDFLAGS=""
LIBS="-lpcap -lnet"

# Function to clean build artifacts
cleanup() {
    local mode=$1  # "all" or "objects"
    echo "Cleaning build artifacts..."
    rm -f *.o
    if [ "$mode" = "all" ]; then
        rm -f ndpresponder
    fi
}

# Clean previous build files
cleanup "all"

echo "Checking for required libraries..."

# Function to check if library headers exist
check_header() {
    local header=$1
    local path=$2
    echo -n "Checking for $header... "
    if [ -f "$path" ]; then
        echo "found"
        return 0
    else
        echo "not found"
        return 1
    fi
}

# First try pkg-config
USE_PKG_CONFIG=1

# Check for libpcap using pkg-config
if ! pkg-config --exists libpcap; then
    echo "Warning: libpcap not found via pkg-config"
    echo "Note: You might have installed libcap-dev instead of libpcap-dev."
    echo "These are different libraries:"
    echo "  - libcap-dev: Linux capabilities library"
    echo "  - libpcap-dev: Packet capture library (required for this program)"
    
    # Fall back to direct header check
    if ! check_header "pcap.h" "/usr/include/pcap/pcap.h"; then
        echo "Error: libpcap headers not found"
        echo "Please install the correct library with:"
        echo "  sudo apt-get install libpcap-dev"
        exit 1
    fi
    USE_PKG_CONFIG=0
fi

# Check for libnet using pkg-config
if ! pkg-config --exists libnet; then
    echo "Warning: libnet not found via pkg-config"

    # Try an alternative name (some distributions use different names)
    if pkg-config --exists libnet1; then
        echo "Found libnet using alternative name 'libnet1'"
        LIBNET_PKG="libnet1"
    else
        # Fall back to direct header check
        if ! check_header "libnet.h" "/usr/include/libnet.h"; then
            echo "Error: libnet headers not found"
            echo "Please install libnet with:"
            echo "  sudo apt-get install libnet1-dev"
            exit 1
        fi
        USE_PKG_CONFIG=0
    fi
else
    LIBNET_PKG="libnet"
fi

# Set up compiler flags
if [ "$USE_PKG_CONFIG" -eq 1 ]; then
    echo "Using pkg-config for library detection"
    CFLAGS="$CFLAGS $(pkg-config --cflags libpcap)"
    LIBS="$(pkg-config --libs libpcap)"
    
    if [ -n "$LIBNET_PKG" ]; then
        CFLAGS="$CFLAGS $(pkg-config --cflags $LIBNET_PKG)"
        LIBS="$(pkg-config --libs $LIBNET_PKG)"
    else
        LIBS="$LIBS -lnet"
    fi
else
    echo "Using manual library detection"
    # Manual configuration for include and library paths
    CFLAGS="$CFLAGS -I/usr/include/pcap"
    LIBS="-lpcap -lnet"
fi

echo "Using CFLAGS: $CFLAGS"
echo "Using LIBS: $LIBS"

echo "Building ndpresponder..."

$CC $CFLAGS -c ndp.c -o ndp.o
$CC $CFLAGS -c hostinfo.c -o hostinfo.o
$CC $CFLAGS -c docker.c -o docker.o
$CC $CFLAGS -c main.c -o main.o

$CC $LDFLAGS -o ndpresponder ndp.o hostinfo.o docker.o main.o $LIBS

echo "Build complete. Binary is: ndpresponder"
chmod +x ndpresponder

# Clean object files after successful build
cleanup "objects"