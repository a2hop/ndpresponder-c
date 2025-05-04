#ifndef DOCKER_H
#define DOCKER_H

#include <netinet/in.h>
#include <stdbool.h>

// Initialize Docker monitoring
int docker_init(const char **networks, int network_count);

// Cleanup Docker resources
void docker_cleanup(void);

// Check if an IP is in a Docker network
bool docker_contains_ip(const struct in6_addr *ip);

// Poll for new Docker IPs (returns 1 if a new IP is found, 0 otherwise)
int docker_poll_new_ip(struct in6_addr *new_ip);

#endif // DOCKER_H
