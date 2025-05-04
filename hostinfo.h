#ifndef HOSTINFO_H
#define HOSTINFO_H

#include <netinet/in.h>
#include <net/if.h>

typedef struct {
    uint8_t host_mac[6];
    struct in6_addr gateway_ip;
    int has_gateway;
} host_info_t;

// Gather information about the host (MAC address, gateway)
int hostinfo_gather(const char *interface, host_info_t *hi);

// Ensure gateway neighbor entry is set to NOARP
int hostinfo_ensure_gateway_neigh(const char *interface, host_info_t *hi);

#endif // HOSTINFO_H
