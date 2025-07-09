/*
 * Copyright (c) 2025 Lucas Kafarski
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the conditions of the BSD 3-Clause
 * License are met.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdarg.h>
#include <ctype.h>
#include "ndp.h"
#include "hostinfo.h"
#include "docker.h"

#define MAX_SUBNETS 64
#define MAX_DOCKER_NETWORKS 64
#define PACKET_BUFFER_SIZE 2048

static pcap_t *pcap_handle = NULL;
static int running = 1;
static host_info_t host_info;
static char *interface_name = NULL;
static char *subnet_list[MAX_SUBNETS];
static int subnet_count = 0;
static char *docker_networks[MAX_DOCKER_NETWORKS];
static int docker_network_count = 0;
static int proactive_mode = 0;  
static int verbose_mode = 0;    

// Add struct to store both the IP address and prefix length
typedef struct {
    struct in6_addr addr;
    int prefix_len;
} ip_prefix_t;

// Change the type of target_subnets array
static ip_prefix_t target_subnets[MAX_SUBNETS];
static int target_subnet_count = 0;

// Add excluded subnets array
static ip_prefix_t excluded_subnets[MAX_SUBNETS];
static int excluded_subnet_count = 0;

// Function to allow external modules to check if verbose mode is enabled
int check_verbose_mode(void) {
    return verbose_mode;
}

// Helper function for conditional logging
static void verbose_log(const char *format, ...) {
    if (verbose_mode) {
        va_list args;
        va_start(args, format);
        vprintf(format, args);
        va_end(args);
    }
}

// For essential logs that should always be shown
static void log_msg(const char *format, ...) {
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}

// Helper function to check if an IP is within a subnet
static int ip_in_subnet(const struct in6_addr *ip, const struct in6_addr *subnet_addr, int prefix_len) {
    // For /128 addresses, do a direct comparison
    if (prefix_len == 128) {
        return memcmp(ip, subnet_addr, sizeof(struct in6_addr)) == 0;
    }
    
    // For other prefixes, compare only the significant bits
    int bytes_to_compare = prefix_len / 8;
    int bits_remaining = prefix_len % 8;
    
    // Debug output for subnet matching
    char ip_str[INET6_ADDRSTRLEN];
    char subnet_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, ip, ip_str, sizeof(ip_str));
    inet_ntop(AF_INET6, subnet_addr, subnet_str, sizeof(subnet_str));
    
    // Compare full bytes
    if (bytes_to_compare > 0 && memcmp(ip->s6_addr, subnet_addr->s6_addr, bytes_to_compare) != 0) {
        return 0;
    }
    
    // If we have remaining bits, compare them
    if (bits_remaining > 0) {
        uint8_t mask = 0xFF << (8 - bits_remaining);
        if ((ip->s6_addr[bytes_to_compare] & mask) != (subnet_addr->s6_addr[bytes_to_compare] & mask)) {
            return 0;
        }
    }
    
    verbose_log("IP %s matches subnet %s/%d\n", ip_str, subnet_str, prefix_len);
    return 1;
}

// Function to check if an IP is in our target subnets
static int is_in_target_subnets(const struct in6_addr *ip) {
    for (int i = 0; i < target_subnet_count; i++) {
        if (ip_in_subnet(ip, &target_subnets[i].addr, target_subnets[i].prefix_len)) {
            return 1;
        }
    }
    return 0;
}

// Function to check if an IP is in excluded subnets
static int is_in_excluded_subnets(const struct in6_addr *ip) {
    for (int i = 0; i < excluded_subnet_count; i++) {
        if (ip_in_subnet(ip, &excluded_subnets[i].addr, excluded_subnets[i].prefix_len)) {
            return 1;
        }
    }
    return 0;
}

// Enhanced signal handler for graceful shutdown
static void handle_signal(int sig) {
    char *sig_name = NULL;
    switch (sig) {
        case SIGINT:
            sig_name = "SIGINT";
            break;
        case SIGTERM:
            sig_name = "SIGTERM";
            break;
        default:
            sig_name = "Unknown signal";
    }
    
    printf("\nReceived %s, shutting down gracefully...\n", sig_name);
    running = 0;
    
    // Break pcap out of capture loop if needed
    if (pcap_handle != NULL) {
        pcap_breakloop(pcap_handle);
    }
}

// Callback for processing neighbor solicitation packets
static void process_solicitation(neigh_solicitation_t *ns) {
    char ns_str[256];
    char target_ip_str[INET6_ADDRSTRLEN];
    char router_ip_str[INET6_ADDRSTRLEN];
    int respond = 0;
    
    ns_to_string(ns, ns_str, sizeof(ns_str));
    inet_ntop(AF_INET6, &ns->target_ip, target_ip_str, sizeof(target_ip_str));
    inet_ntop(AF_INET6, &ns->router_ip, router_ip_str, sizeof(router_ip_str));
    
    // Check if IP is in excluded subnets first
    if (is_in_excluded_subnets(&ns->target_ip)) {
        verbose_log("Ignoring solicitation for %s (excluded subnet) from %s\n", target_ip_str, router_ip_str);
        return;
    }
    
    // Check if we should respond
    if (docker_contains_ip(&ns->target_ip)) {
        verbose_log("Solicitation for %s (Docker container) from %s\n", target_ip_str, router_ip_str);
        respond = 1;
    } else if (ipv6_is_multicast(&ns->dest_ip) && is_in_target_subnets(&ns->target_ip)) {
        verbose_log("Solicitation for %s (static subnet) from %s\n", target_ip_str, router_ip_str);
        respond = 1;
    } else {
        verbose_log("Ignoring solicitation for %s from %s\n", target_ip_str, router_ip_str);
    }
    
    if (respond) {
        uint8_t packet[PACKET_BUFFER_SIZE];
        size_t len = sizeof(packet);
        
        if (ndp_create_response(ns, packet, &len, host_info.host_mac) == 0) {
            if (verbose_mode) {
                printf("Responding to solicitation for %s from %s\n", target_ip_str, router_ip_str);
            }
            
            // Skip libnet_write and directly inject the packet using pcap
            if (pcap_inject(pcap_handle, packet, len) < 0) {
                fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(pcap_handle));
            } else {
                verbose_log("Packet injected successfully (%zu bytes)\n", len);
                
                // For maximum compatibility, inject the packet again after a short delay
                usleep(1000);  // 1ms delay
                if (pcap_inject(pcap_handle, packet, len) < 0) {
                    fprintf(stderr, "Error sending second packet: %s\n", pcap_geterr(pcap_handle));
                } else {
                    verbose_log("Second packet injected successfully\n");
                }
            }
        }
    }
}

static void handle_docker_events() {
    struct in6_addr new_ip;
    uint8_t packet[PACKET_BUFFER_SIZE];
    size_t len;
    
    while (docker_poll_new_ip(&new_ip)) {
        char ip_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &new_ip, ip_str, sizeof(ip_str));
        
        // Send gratuitous neighbor advertisement
        len = sizeof(packet);
        if (ndp_create_gratuitous(packet, &len, host_info.host_mac, &new_ip) == 0) {
            printf("Sending gratuitous advertisement for %s\n", ip_str);
            if (pcap_inject(pcap_handle, packet, len) < 0) {
                fprintf(stderr, "Error sending gratuitous packet: %s\n", 
                       pcap_geterr(pcap_handle));
            }
        }
        
        // Send neighbor solicitation to gateway if we have one
        if (host_info.has_gateway) {
            len = sizeof(packet);
            if (ndp_create_solicit(packet, &len, host_info.host_mac, &new_ip, 
                                  &host_info.gateway_ip) == 0) {
                printf("Sending solicitation to gateway for %s\n", ip_str);
                if (pcap_inject(pcap_handle, packet, len) < 0) {
                    fprintf(stderr, "Error sending solicitation packet: %s\n", 
                           pcap_geterr(pcap_handle));
                }
            }
        }
    }
}

// New function to parse configuration file
static int parse_config_file(const char *filename) {
    FILE *fp;
    char line[256];
    char *value;
    
    fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open config file %s: %s\n", filename, strerror(errno));
        return -1;
    }
    
    printf("Reading configuration from %s\n", filename);
    
    while (fgets(line, sizeof(line), fp)) {
        // Remove trailing newline and carriage return
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') {
            line[len-1] = '\0';
            len--;
        }
        if (len > 0 && line[len-1] == '\r') {
            line[len-1] = '\0';
            len--;
        }
        
        // Skip empty lines and comments
        if (len == 0 || line[0] == '#' || line[0] == ';') {
            continue;
        }
        
        // Process "link" lines - set interface
        if (strncmp(line, "link", 4) == 0 && isspace(line[4])) {
            value = line + 4;
            while (isspace(*value)) value++;
            
            if (*value) {
                if (interface_name) {
                    free(interface_name);
                }
                interface_name = strdup(value);
                verbose_log("Config: Using interface %s\n", interface_name);
            }
            continue;
        }
        
        // Process "net" lines - add subnet
        if (strncmp(line, "net", 3) == 0 && isspace(line[3])) {
            value = line + 3;
            while (isspace(*value)) value++;
            
            if (*value && subnet_count < MAX_SUBNETS) {
                subnet_list[subnet_count++] = strdup(value);
                verbose_log("Config: Added subnet %s\n", value);
            }
            continue;
        }

        // Process "nix" lines - add excluded subnet
        if (strncmp(line, "nix", 3) == 0 && isspace(line[3])) {
            value = line + 3;
            while (isspace(*value)) value++;
            
            if (*value && excluded_subnet_count < MAX_SUBNETS) {
                char *subnet_str = strdup(value);
                if (!subnet_str) {
                    fprintf(stderr, "Failed to allocate memory for excluded subnet\n");
                    continue;
                }
                
                char *slash = strchr(subnet_str, '/');
                int prefix_len = 128; // Default to /128 if no prefix is specified
                
                if (slash) {
                    *slash = '\0';  // Temporarily remove prefix length
                    prefix_len = atoi(slash + 1);
                    
                    if (prefix_len < 0 || prefix_len > 128) {
                        fprintf(stderr, "Invalid prefix length in excluded subnet %s, using /128\n", value);
                        prefix_len = 128;
                    }
                }
                
                if (inet_pton(AF_INET6, subnet_str, &excluded_subnets[excluded_subnet_count].addr) != 1) {
                    fprintf(stderr, "Invalid IPv6 excluded subnet: %s\n", value);
                } else {
                    excluded_subnets[excluded_subnet_count].prefix_len = prefix_len;
                    
                    char ip_str[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, &excluded_subnets[excluded_subnet_count].addr, ip_str, sizeof(ip_str));
                    printf("Added excluded subnet: %s/%d\n", ip_str, prefix_len);
                    
                    excluded_subnet_count++;
                }
                
                free(subnet_str);
                verbose_log("Config: Added excluded subnet %s\n", value);
            }
            continue;
        }

        // Process "docker" lines - add Docker network
        if (strncmp(line, "docker", 6) == 0 && isspace(line[6])) {
            value = line + 6;
            while (isspace(*value)) value++;
            
            if (*value && docker_network_count < MAX_DOCKER_NETWORKS) {
                docker_networks[docker_network_count++] = strdup(value);
                verbose_log("Config: Added Docker network %s\n", value);
            }
            continue;
        }

        // Process "proactive" option
        if (strncmp(line, "proactive", 9) == 0) {
            proactive_mode = 1;
            verbose_log("Config: Enabled proactive mode\n");
            continue;
        }

        // Process "verbose" option in config file too
        if (strncmp(line, "verbose", 7) == 0) {
            verbose_mode = 1;
            verbose_log("Config: Enabled verbose mode\n");
            continue;
        }
    }
    
    fclose(fp);
    return 0;
}

static void print_usage(const char *progname) {
    printf("Usage: %s [OPTIONS]\n", progname);
    printf("IPv6 Neighbor Discovery Protocol Responder\n\n");
    printf("Options:\n");
    printf("  -i, --interface INTERFACE  Uplink network interface\n");
    printf("  -n, --subnet SUBNET        Static target subnet (IPv6/mask)\n");
    printf("  -N, --docker-network NAME  Docker network name\n");
    printf("  -p, --proactive            Proactively announce IPs at startup\n");
    printf("  -c, --config FILE          Read configuration from FILE\n");
    printf("  -v, --verbose              Enable verbose output\n");
    printf("  -h, --help                 Show this help message\n");
}

static void parse_args(int argc, char *argv[]) {
    int i = 1;
    
    while (i < argc) {
        if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interface") == 0) {
            if (i + 1 < argc) {
                interface_name = strdup(argv[i + 1]);
                i += 2;
            } else {
                fprintf(stderr, "Error: Missing argument for %s\n", argv[i]);
                exit(1);
            }
        } else if (strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "--subnet") == 0) {
            if (i + 1 < argc && subnet_count < MAX_SUBNETS) {
                subnet_list[subnet_count++] = strdup(argv[i + 1]);
                i += 2;
            } else {
                fprintf(stderr, "Error: Missing argument for %s or too many subnets\n", argv[i]);
                exit(1);
            }
        } else if (strcmp(argv[i], "-N") == 0 || strcmp(argv[i], "--docker-network") == 0) {
            if (i + 1 < argc && docker_network_count < MAX_DOCKER_NETWORKS) {
                docker_networks[docker_network_count++] = strdup(argv[i + 1]);
                i += 2;
            } else {
                fprintf(stderr, "Error: Missing argument for %s or too many networks\n", argv[i]);
                exit(1);
            }
        } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--proactive") == 0) {
            proactive_mode = 1;
            i++;
        } else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--config") == 0) {
            if (i + 1 < argc) {
                if (parse_config_file(argv[i + 1]) < 0) {
                    exit(1);
                }
                i += 2;
            } else {
                fprintf(stderr, "Error: Missing argument for %s\n", argv[i]);
                exit(1);
            }
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose_mode = 1;
            i++;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            exit(0);
        } else {
            fprintf(stderr, "Error: Unknown option %s\n", argv[i]);
            print_usage(argv[0]);
            exit(1);
        }
    }
    
    // Interface name can be set in config file, so only check after parsing everything
    if (!interface_name) {
        fprintf(stderr, "Error: Interface name is required (use -i or 'link' in config file)\n");
        print_usage(argv[0]);
        exit(1);
    }
}

// New function to send gratuitous advertisements for all IPs
static void announce_all_ips(void) {
    uint8_t packet[PACKET_BUFFER_SIZE];
    size_t len;

    printf("Proactively announcing all configured IP addresses...\n");
    
    // Announce target subnets
    for (int i = 0; i < target_subnet_count; i++) {
        // For subnet prefixes that aren't /128, just announce the subnet address
        char ip_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &target_subnets[i].addr, ip_str, sizeof(ip_str));
        
        printf("Announcing IP: %s/%d\n", ip_str, target_subnets[i].prefix_len);
        
        len = sizeof(packet);
        if (ndp_create_gratuitous(packet, &len, host_info.host_mac, &target_subnets[i].addr) == 0) {
            if (pcap_inject(pcap_handle, packet, len) < 0) {
                fprintf(stderr, "Error sending gratuitous packet: %s\n", pcap_geterr(pcap_handle));
            }
        }
        
        // Small delay between packets
        usleep(100000);  // 100ms
    }
}

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr *pkthdr;
    const u_char *packet;
    int ret;
    
    // Check for root privileges
    if (geteuid() != 0) {
        fprintf(stderr, "Error: This program requires root privileges to run.\n");
        fprintf(stderr, "Please run with sudo or as root:\n");
        fprintf(stderr, "  sudo %s [options]\n", argv[0]);
        fprintf(stderr, "Alternatively, you can set the CAP_NET_RAW capability on the executable:\n");
        fprintf(stderr, "  sudo setcap cap_net_raw+ep %s\n", argv[0]);
        return 1;
    }
    
    // Parse command line arguments
    parse_args(argc, argv);
    
    // Set up signal handlers with more signals for better cleanup
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    
    sigaction(SIGINT, &sa, NULL);   // Ctrl+C
    sigaction(SIGTERM, &sa, NULL);  // kill command
    sigaction(SIGHUP, &sa, NULL);   // Terminal closed
    sigaction(SIGQUIT, &sa, NULL);  // Ctrl+Backslash
    
    // Gather host information
    if (hostinfo_gather(interface_name, &host_info) < 0) {
        fprintf(stderr, "Failed to gather host information\n");
        return 1;
    }
    
    // Initialize NDP
    if (ndp_init(interface_name) < 0) {
        fprintf(stderr, "Failed to initialize NDP\n");
        return 1;
    }
    
    // Parse target subnets with prefix lengths
    for (int i = 0; i < subnet_count; i++) {
        char *subnet_str = strdup(subnet_list[i]);
        if (!subnet_str) {
            fprintf(stderr, "Failed to allocate memory for subnet\n");
            continue;
        }
        
        char *slash = strchr(subnet_str, '/');
        int prefix_len = 128; // Default to /128 if no prefix is specified
        
        if (slash) {
            *slash = '\0';  // Temporarily remove prefix length
            prefix_len = atoi(slash + 1);
            
            if (prefix_len < 0 || prefix_len > 128) {
                fprintf(stderr, "Invalid prefix length in %s, using /128\n", subnet_list[i]);
                prefix_len = 128;
            }
        }
        
        if (inet_pton(AF_INET6, subnet_str, &target_subnets[target_subnet_count].addr) != 1) {
            fprintf(stderr, "Invalid IPv6 subnet: %s\n", subnet_list[i]);
        } else {
            target_subnets[target_subnet_count].prefix_len = prefix_len;
            
            char ip_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &target_subnets[target_subnet_count].addr, ip_str, sizeof(ip_str));
            printf("Added target subnet: %s/%d\n", ip_str, prefix_len);
            
            target_subnet_count++;
        }
        
        free(subnet_str);
    }
    
    // Note: Excluded subnets are already parsed in parse_config_file()
    // No need to parse them again here
    
    // Initialize Docker if needed
    if (docker_network_count > 0) {
        const char *networks[MAX_DOCKER_NETWORKS];
        for (int i = 0; i < docker_network_count; i++) {
            networks[i] = docker_networks[i];
        }
        
        if (docker_init(networks, docker_network_count) < 0) {
            fprintf(stderr, "Warning: Failed to initialize Docker monitoring\n");
        }
    }
    
    // Set a shorter timeout for pcap to ensure frequent checks of the running flag
    pcap_handle = pcap_open_live(interface_name, BUFSIZ, 1, 10, errbuf);
    if (pcap_handle == NULL) {
        fprintf(stderr, "Failed to open interface %s: %s\n", interface_name, errbuf);
        ndp_cleanup();
        docker_cleanup();
        return 1;
    }
    
    // Setup BPF filter
    if (ndp_setup_filter(pcap_handle) < 0) {
        pcap_close(pcap_handle);
        ndp_cleanup();
        docker_cleanup();
        return 1;
    }
    
    // Show startup banner with mode information
    log_msg("NDP responder started on interface %s\n", interface_name);
    if (!verbose_mode) {
        log_msg("Running in quiet mode. Use -v for verbose output.\n");
        // Removed the line about dots
    }
    
    // If proactive mode is enabled, announce all IPs
    if (proactive_mode) {
        announce_all_ips();
    }
    
    // Main loop
    while (running) {
        // Check running flag at the start of each iteration
        if (!running) {
            break;
        }
        
        // Non-blocking packet capture with a short timeout
        ret = pcap_next_ex(pcap_handle, &pkthdr, &packet);
        
        // Immediately check running flag again after pcap
        if (!running) {
            break;
        }
        
        if (ret == 1) {
            // Process the packet
            ndp_process_packet((u_char *)process_solicitation, pkthdr, packet);
        } else if (ret == 0) {
            // Timeout, check for Docker events
            if (docker_network_count > 0) {
                handle_docker_events();
            }
        } else if (ret == -1) {
            if (running) {  // Only show error if not caused by pcap_breakloop
                fprintf(stderr, "Error reading packet: %s\n", pcap_geterr(pcap_handle));
            }
            break;
        } else if (ret == -2) {
            // Got pcap_breakloop signal, just exit loop
            printf("Capture loop interrupted\n");
            break;
        }
        
        // Small sleep to prevent CPU hogging
        usleep(10000);  // 10ms
    }
    
    // Enhanced cleanup section
    printf("Performing cleanup...\n");
    
    if (pcap_handle != NULL) {
        pcap_close(pcap_handle);
        pcap_handle = NULL;
    }
    
    ndp_cleanup();
    docker_cleanup();
    
    if (interface_name != NULL) {
        free(interface_name);
        interface_name = NULL;
    }
    
    for (int i = 0; i < subnet_count; i++) {
        if (subnet_list[i] != NULL) {
            free(subnet_list[i]);
            subnet_list[i] = NULL;
        }
    }
    
    for (int i = 0; i < docker_network_count; i++) {
        if (docker_networks[i] != NULL) {
            free(docker_networks[i]);
            docker_networks[i] = NULL;
        }
    }
    
    printf("NDP responder stopped cleanly\n");
    return 0;
}
