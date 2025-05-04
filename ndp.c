#include "ndp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <net/ethernet.h>

// Define ND_OPT_NONCE if not already defined (value is 14)
#ifndef ND_OPT_NONCE
#define ND_OPT_NONCE 14
#endif

static libnet_t *l = NULL;

// BPF filter for ICMPv6 neighbor solicitation
static struct bpf_program ndp_bpf_filter;
static const char *filter_expr = "icmp6 and ip6[40] == 135";

int ndp_init(const char *interface) {
    char errbuf[LIBNET_ERRBUF_SIZE];
    
    l = libnet_init(LIBNET_LINK, interface, errbuf);
    if (l == NULL) {
        fprintf(stderr, "libnet_init failed: %s\n", errbuf);
        return -1;
    }
    
    return 0;
}

void ndp_cleanup(void) {
    if (l != NULL) {
        libnet_destroy(l);
        l = NULL;
    }
}

int ndp_setup_filter(pcap_t *handle) {
    if (pcap_compile(handle, &ndp_bpf_filter, filter_expr, 1, PCAP_NETMASK_UNKNOWN) < 0) {
        fprintf(stderr, "Error compiling BPF filter: %s\n", pcap_geterr(handle));
        return -1;
    }
    
    if (pcap_setfilter(handle, &ndp_bpf_filter) < 0) {
        fprintf(stderr, "Error setting BPF filter: %s\n", pcap_geterr(handle));
        pcap_freecode(&ndp_bpf_filter);
        return -1;
    }
    
    return 0;
}

bool ipv6_is_multicast(const struct in6_addr *addr) {
    return addr->s6_addr[0] == 0xFF;
}

int ndp_create_gratuitous(uint8_t *buffer, size_t *len, 
                         const uint8_t *host_mac, const struct in6_addr *target_ip) {
    
    libnet_clear_packet(l);
    libnet_ptag_t ptag;
    struct libnet_in6_addr dst_libnet, src_libnet, target_libnet;
    
    // Create multicast destination MAC based on target IP
    uint8_t dst_mac[6] = {0x33, 0x33, 0xFF};
    memcpy(dst_mac + 3, &target_ip->s6_addr[13], 3);
    
    // Create multicast destination IP for solicited-node multicast address
    struct in6_addr dst_ip;
    memset(&dst_ip, 0, sizeof(dst_ip));
    dst_ip.s6_addr[0] = 0xFF;
    dst_ip.s6_addr[1] = 0x02;
    dst_ip.s6_addr[11] = 0x01;
    dst_ip.s6_addr[12] = 0xFF;
    memcpy(&dst_ip.s6_addr[13], &target_ip->s6_addr[13], 3);
    
    // Generate random nonce
    uint8_t nonce[6];
    // Use a more robust random source if available, but rand() is simple
    for (int i = 0; i < 6; i++) {
        nonce[i] = rand() % 256;
    }
    
    // Convert IPv6 addresses to libnet format
    // Source IP is unspecified (::) for DAD-like messages
    memset(&src_libnet, 0, sizeof(src_libnet)); 
    memcpy(&dst_libnet, &dst_ip, sizeof(struct in6_addr));
    memcpy(&target_libnet, target_ip, sizeof(struct in6_addr));
    
    // Build the packet in reverse order (LIFO)
    
    // 1. Create ICMPv6 Nonce Option (Type 14) - Matching Go code
    uint8_t *opt_data = malloc(6);
    if (!opt_data) {
        fprintf(stderr, "Error allocating memory for options\n");
        return -1;
    }
    memcpy(opt_data, nonce, 6);
    ptag = libnet_build_icmpv6_ndp_opt(
        ND_OPT_NONCE, // Use Nonce option type (14)
        opt_data,
        6, // Nonce data length
        l,
        0);
    
    if (ptag == -1) {
        fprintf(stderr, "Error building ICMPv6 NDP Nonce option: %s\n", libnet_geterror(l));
        free(opt_data);
        return -1;
    }
    
    // 2. Create ICMPv6 Neighbor Solicitation
    ptag = libnet_build_icmpv6_ndp_nsol(
        ND_NEIGHBOR_SOLICIT,
        0,
        0,
        target_libnet,
        NULL, // No payload for the solicitation itself
        0,    // Payload size 0
        l,
        0);
    
    if (ptag == -1) {
        fprintf(stderr, "Error building ICMPv6 NDP solicit: %s\n", libnet_geterror(l));
        free(opt_data);
        return -1;
    }
    
    // 3. Create IPv6 header
    // Payload length = ICMPv6 base header (8) + NS header (16) + Option header (2) + Option data (6) = 32
    ptag = libnet_build_ipv6(
        0, // Traffic class
        0, // Flow label
        LIBNET_ICMPV6_H + LIBNET_ICMPV6_NDP_NSOL_H + 8, // Payload length: ICMPv6 + NS + Option(8 bytes total)
        IPPROTO_ICMPV6, // Next header
        255,            // Hop limit
        src_libnet,     // Source IP (::)
        dst_libnet,     // Destination IP (Solicited-Node Multicast)
        NULL,           // Payload
        0,              // Payload size
        l,
        0);
    
    if (ptag == -1) {
        fprintf(stderr, "Error building IPv6 header: %s\n", libnet_geterror(l));
        free(opt_data);
        return -1;
    }
    
    // 4. Create Ethernet header
    ptag = libnet_build_ethernet(
        dst_mac,        // Destination MAC (Multicast)
        host_mac,       // Source MAC
        ETHERTYPE_IPV6, // EtherType
        NULL,
        0,
        l,
        0);
    
    if (ptag == -1) {
        fprintf(stderr, "Error building Ethernet header: %s\n", libnet_geterror(l));
        free(opt_data);
        return -1;
    }
    
    // Write the packet
    size_t packet_size = libnet_write(l);
    if (packet_size == -1) {
        fprintf(stderr, "Error writing packet: %s\n", libnet_geterror(l));
        free(opt_data);
        return -1;
    }
    
    printf("Gratuitous NDP solicitation sent (%zu bytes)\n", packet_size);

    // Copy the packet into buffer if needed
    if (buffer != NULL && len != NULL) {
        *len = packet_size;
        u_char *packet = libnet_getpbuf(l, 0); // Use 0 as ptag to get the entire packet
        if (packet) {
            memcpy(buffer, packet, *len);
        }
    }
    
    free(opt_data);
    return 0;
}

int ndp_create_solicit(uint8_t *buffer, size_t *len, 
                      const uint8_t *host_mac, const struct in6_addr *src_ip,
                      const struct in6_addr *gateway_ip) {
    
    libnet_clear_packet(l);
    libnet_ptag_t ptag;
    struct libnet_in6_addr src_libnet, dst_libnet, gw_libnet;
    
    // Create solicited-node multicast MAC address for the *gateway*
    uint8_t dst_mac[6] = {0x33, 0x33, 0xFF};
    memcpy(dst_mac + 3, &gateway_ip->s6_addr[13], 3); // Use gateway IP bytes
    
    // Create solicited-node multicast destination IP for the *gateway*
    struct in6_addr dst_ip;
    memset(&dst_ip, 0, sizeof(dst_ip));
    dst_ip.s6_addr[0] = 0xFF;
    dst_ip.s6_addr[1] = 0x02;
    dst_ip.s6_addr[11] = 0x01;
    dst_ip.s6_addr[12] = 0xFF;
    memcpy(&dst_ip.s6_addr[13], &gateway_ip->s6_addr[13], 3); // Use gateway IP bytes
    
    // Convert IPv6 addresses to libnet format
    memcpy(&src_libnet, src_ip, sizeof(struct in6_addr));
    memcpy(&dst_libnet, &dst_ip, sizeof(struct in6_addr)); // Use correct destination IP
    memcpy(&gw_libnet, gateway_ip, sizeof(struct in6_addr));
    
    // Build the packet in reverse order
    
    // 1. Create ICMPv6 Neighbor Solicitation options (source link-layer address)
    uint8_t *mac_copy = malloc(6);
    if (!mac_copy) {
        fprintf(stderr, "Error allocating memory for MAC\n");
        return -1;
    }
    memcpy(mac_copy, host_mac, 6);
    
    ptag = libnet_build_icmpv6_ndp_opt(
        ND_OPT_SOURCE_LINKADDR, // Type 1
        mac_copy,
        6, // MAC data length
        l,
        0);
    
    if (ptag == -1) {
        fprintf(stderr, "Error building ICMPv6 NDP SLLAO option: %s\n", libnet_geterror(l));
        free(mac_copy);
        return -1;
    }
    
    // 2. Create ICMPv6 Neighbor Solicitation
    ptag = libnet_build_icmpv6_ndp_nsol(
        ND_NEIGHBOR_SOLICIT,
        0,
        0,
        gw_libnet, // Target address is the gateway IP
        NULL,
        0,
        l,
        0);
    
    if (ptag == -1) {
        fprintf(stderr, "Error building ICMPv6 NDP solicit: %s\n", libnet_geterror(l));
        free(mac_copy);
        return -1;
    }
    
    // 3. Create IPv6 header
    // Payload length = ICMPv6 base (8) + NS (16) + Option (8) = 32
    ptag = libnet_build_ipv6(
        0,
        0,
        LIBNET_ICMPV6_H + LIBNET_ICMPV6_NDP_NSOL_H + 8, // Payload length
        IPPROTO_ICMPV6,
        255,            // Hop limit
        src_libnet,     // Source IP
        dst_libnet,     // Destination IP (Solicited-Node Multicast of Gateway)
        NULL,
        0,
        l,
        0);
    
    if (ptag == -1) {
        fprintf(stderr, "Error building IPv6 header: %s\n", libnet_geterror(l));
        free(mac_copy);
        return -1;
    }
    
    // 4. Create Ethernet header
    ptag = libnet_build_ethernet(
        dst_mac,        // Destination MAC (Solicited-Node Multicast of Gateway)
        host_mac,       // Source MAC
        ETHERTYPE_IPV6,
        NULL,
        0,
        l,
        0);
    
    if (ptag == -1) {
        fprintf(stderr, "Error building Ethernet header: %s\n", libnet_geterror(l));
        free(mac_copy);
        return -1;
    }
    
    // Write the packet
    size_t packet_size = libnet_write(l);
    if (packet_size == -1) {
        fprintf(stderr, "Error writing packet: %s\n", libnet_geterror(l));
        free(mac_copy);
        return -1;
    }
    
    printf("NDP solicitation to gateway sent (%zu bytes)\n", packet_size);

    // Copy the packet into buffer if needed
    if (buffer != NULL && len != NULL) {
        *len = packet_size;
        u_char *packet = libnet_getpbuf(l, 0); // Use 0 as ptag to get the entire packet
        if (packet) {
            memcpy(buffer, packet, *len);
        }
    }
    
    free(mac_copy);
    return 0;
}

// Helper function for conditional logging that takes a function pointer
static void verbose_log(const char *format, ...) {
    // Use a function pointer to check if verbose mode is enabled
    extern int check_verbose_mode(void);
    
    if (check_verbose_mode()) {
        va_list args;
        va_start(args, format);
        vprintf(format, args);
        va_end(args);
    }
}

int ndp_create_response(const neigh_solicitation_t *ns, uint8_t *buffer, size_t *len,
                       const uint8_t *host_mac) {
    // Log the response we're creating (for debugging) - now conditional
    char target_ip_str[INET6_ADDRSTRLEN];
    char router_ip_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ns->target_ip, target_ip_str, sizeof(target_ip_str));
    inet_ntop(AF_INET6, &ns->router_ip, router_ip_str, sizeof(router_ip_str));
    verbose_log("Creating response: target=%s, router=%s\n", target_ip_str, router_ip_str);
    
    // Print router MAC for debugging - now conditional
    verbose_log("Router MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
           ns->router_mac[0], ns->router_mac[1], ns->router_mac[2],
           ns->router_mac[3], ns->router_mac[4], ns->router_mac[5]);
    
    // Print host MAC for debugging - now conditional
    verbose_log("Host MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
           host_mac[0], host_mac[1], host_mac[2],
           host_mac[3], host_mac[4], host_mac[5]);
    
    // Direct packet creation instead of using libnet
    // This ensures we have complete control over all packet bytes
    
    // Allocate buffer for the entire packet
    // Ethernet(14) + IPv6(40) + ICMPv6(8) + NA(16) + Option(8) = 86 bytes
    uint8_t packet[96];
    memset(packet, 0, sizeof(packet));
    
    // Current position in the packet
    int pos = 0;
    
    // 1. Ethernet header (14 bytes)
    // Destination MAC (router's MAC)
    memcpy(packet + pos, ns->router_mac, 6);
    pos += 6;
    
    // Source MAC (our MAC)
    memcpy(packet + pos, host_mac, 6);
    pos += 6;
    
    // EtherType (IPv6 = 0x86DD)
    packet[pos++] = 0x86;
    packet[pos++] = 0xDD;
    
    // 2. IPv6 header (40 bytes)
    // Version (6) and Traffic Class / Flow Label
    packet[pos++] = 0x60;  // Version 6, no TC or FL
    packet[pos++] = 0x00;  // No TC or FL
    packet[pos++] = 0x00;  // No FL
    packet[pos++] = 0x00;  // No FL
    
    // Payload Length (ICMPv6 + ND_NA + Option = 8 + 16 + 8 = 32 bytes)
    uint16_t payload_len = 32;  // Fixed to the correct size
    packet[pos++] = (payload_len >> 8) & 0xFF;  // High byte
    packet[pos++] = payload_len & 0xFF;         // Low byte
    
    // Next Header (ICMPv6 = 58)
    packet[pos++] = IPPROTO_ICMPV6;
    
    // Hop Limit (255 for NDP)
    packet[pos++] = 255;
    
    // Source IP (target IP from solicitation)
    memcpy(packet + pos, &ns->target_ip, 16);
    pos += 16;
    
    // Destination IP (router's IP)
    memcpy(packet + pos, &ns->router_ip, 16);
    pos += 16;
    
    // 3. ICMPv6 header start (4 bytes)
    // Type (Neighbor Advertisement = 136)
    packet[pos++] = ND_NEIGHBOR_ADVERT;
    
    // Code (0)
    packet[pos++] = 0;
    
    // Checksum (to be filled in later)
    int checksum_pos = pos;  // Remember where the checksum goes
    packet[pos++] = 0;
    packet[pos++] = 0;
    
    // 4. ICMPv6 Neighbor Advertisement (16 bytes)
    // Flags (Router | Solicited | Override = 0xE0)
    uint32_t flags = 0xE0;  // All flags set as in the Go code
    packet[pos++] = flags;
    
    // Reserved (3 bytes)
    packet[pos++] = 0;
    packet[pos++] = 0;
    packet[pos++] = 0;
    
    // Target Address (16 bytes)
    memcpy(packet + pos, &ns->target_ip, 16);
    pos += 16;
    
    // 5. ICMPv6 Option (8 bytes)
    // Type (Target Link-Layer Address = 2)
    packet[pos++] = ND_OPT_TARGET_LINKADDR;
    
    // Length (1 unit = 8 bytes)
    packet[pos++] = 1;
    
    // Link-Layer Address (our MAC)
    memcpy(packet + pos, host_mac, 6);
    pos += 6;
    
    // Calculate ICMPv6 checksum - use a simpler approach
    // ICMPv6 checksum covers IPv6 pseudo-header and ICMPv6 data
    
    // Create a buffer for the pseudo-header + ICMPv6 data
    uint8_t *checksum_data = malloc(40 + payload_len);
    if (!checksum_data) {
        fprintf(stderr, "Failed to allocate memory for checksum calculation\n");
        return -1;
    }
    
    // Copy source IP (16 bytes)
    memcpy(checksum_data, &ns->target_ip, 16);
    
    // Copy destination IP (16 bytes)
    memcpy(checksum_data + 16, &ns->router_ip, 16);
    
    // Copy payload length (4 bytes, network byte order)
    uint32_t plen = htonl(payload_len);
    memcpy(checksum_data + 32, &plen, 4);
    
    // Set zeros and next header (4 bytes)
    checksum_data[36] = 0;
    checksum_data[37] = 0;
    checksum_data[38] = 0;
    checksum_data[39] = IPPROTO_ICMPV6;
    
    // Copy ICMPv6 message (payload_len bytes)
    memcpy(checksum_data + 40, packet + 54, payload_len);
    
    // Calculate checksum - using byte-by-byte method to avoid alignment issues
    uint32_t sum = 0;
    for (int i = 0; i < 40 + payload_len - 1; i += 2) {
        sum += (checksum_data[i] << 8) + checksum_data[i+1];
    }
    
    // Add the final byte if odd length
    if ((40 + payload_len) % 2 != 0) {
        sum += checksum_data[40 + payload_len - 1] << 8;
    }
    
    // Fold 32-bit sum into 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    // Take one's complement
    uint16_t checksum = ~sum;
    
    // Insert checksum into the packet
    packet[checksum_pos] = (checksum >> 8) & 0xFF;
    packet[checksum_pos + 1] = checksum & 0xFF;
    
    free(checksum_data);
    
    verbose_log("Using NDP Advertisement flags: 0x%02X\n", flags);
    verbose_log("Direct packet created with %d bytes (payload: %d bytes)\n", pos, payload_len);
    
    // Copy the packet into the output buffer
    if (buffer != NULL && len != NULL) {
        if (*len < pos) {
            fprintf(stderr, "Buffer too small for packet\n");
            return -1;
        }
        memcpy(buffer, packet, pos);
        *len = pos;
    }
    
    return 0;
}

void ndp_process_packet(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    neigh_solicitation_t ns;
    
    // Parse Ethernet header
    struct ether_header *eth_hdr = (struct ether_header *)packet;
    if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IPV6) {
        return;
    }
    
    // Save source MAC
    memcpy(ns.router_mac, eth_hdr->ether_shost, 6);
    
    // Parse IPv6 header
    struct ip6_hdr *ipv6_hdr = (struct ip6_hdr *)(packet + sizeof(struct ether_header));
    if (ipv6_hdr->ip6_nxt != IPPROTO_ICMPV6) {
        return;
    }
    
    // Save source and destination IP
    memcpy(&ns.router_ip, &ipv6_hdr->ip6_src, sizeof(struct in6_addr));
    memcpy(&ns.dest_ip, &ipv6_hdr->ip6_dst, sizeof(struct in6_addr));
    
    // Parse ICMPv6 header
    struct icmp6_hdr *icmp6_hdr = (struct icmp6_hdr *)((uint8_t *)ipv6_hdr + sizeof(struct ip6_hdr));
    if (icmp6_hdr->icmp6_type != ND_NEIGHBOR_SOLICIT) {
        return;
    }
    
    // Parse Neighbor Solicitation message
    struct nd_neighbor_solicit *ndp_sol = (struct nd_neighbor_solicit *)icmp6_hdr;
    memcpy(&ns.target_ip, &ndp_sol->nd_ns_target, sizeof(struct in6_addr));
    
    // Pass the solicitation to the user callback
    void (*callback)(neigh_solicitation_t *) = (void (*)(neigh_solicitation_t *))user_data;
    if (callback) {
        callback(&ns);
    }
}

char *ns_to_string(const neigh_solicitation_t *ns, char *buffer, size_t size) {
    char target_ip[INET6_ADDRSTRLEN];
    char router_ip[INET6_ADDRSTRLEN];
    
    inet_ntop(AF_INET6, &ns->target_ip, target_ip, sizeof(target_ip));
    inet_ntop(AF_INET6, &ns->router_ip, router_ip, sizeof(router_ip));
    
    if (ipv6_is_multicast(&ns->dest_ip)) {
        snprintf(buffer, size, "who-has %s tell %s", target_ip, router_ip);
    } else {
        snprintf(buffer, size, "is-alive %s tell %s", target_ip, router_ip);
    }
    
    return buffer;
}
