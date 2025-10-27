#ifndef NDP_H
#define NDP_H

#include <sys/types.h>
#include <stdint.h>
#include <pcap.h>
#include <libnet.h>
#include <netinet/in.h>
#include <stdbool.h>

#define IPV6_ADDR_LEN 16

// NeighSolicitation contains information from an ICMPv6 neighbor solicitation packet
typedef struct {
    uint8_t router_mac[6];
    struct in6_addr router_ip;
    struct in6_addr dest_ip;
    struct in6_addr target_ip;
} neigh_solicitation_t;

// Initialize NDP responder
int ndp_init(const char *interface);
void ndp_cleanup(void);

// Create a gratuitous ICMPv6 neighbor solicitation packet
int ndp_create_gratuitous(uint8_t *buffer, size_t *len, 
                        const uint8_t *host_mac, const struct in6_addr *target_ip);

// Create an ICMPv6 neighbor solicitation packet
int ndp_create_solicit(uint8_t *buffer, size_t *len, 
                      const uint8_t *host_mac, const struct in6_addr *src_ip,
                      const struct in6_addr *gateway_ip);

// Process neighbor solicitation and create a response
int ndp_create_response(const neigh_solicitation_t *ns, uint8_t *buffer, size_t *len,
                       const uint8_t *host_mac);

// Callback function for packet processing
void ndp_process_packet(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);

// Setup BPF filter for NDP packets
int ndp_setup_filter(pcap_t *handle);

// Check if IPv6 address is multicast
bool ipv6_is_multicast(const struct in6_addr *addr);

// String representation of neighbor solicitation
char *ns_to_string(const neigh_solicitation_t *ns, char *buffer, size_t size);

#endif // NDP_H
