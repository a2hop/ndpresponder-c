/*
 * Copyright (c) 2023 Lucas Kafarski
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the conditions of the BSD 3-Clause
 * License are met.
 */

#include "docker.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/wait.h>

#define MAX_IPS 1024
#define IP_BUFFER_SIZE 46

static const char **docker_network_names = NULL;
static int docker_network_count = 0;
static struct in6_addr docker_ips[MAX_IPS];
static int docker_ip_count = 0;
static struct in6_addr docker_new_ips[MAX_IPS];
static int docker_new_ip_count = 0;
static int docker_new_ip_index = 0;

// Forward declaration of docker_refresh_network function
static int docker_refresh_network(const char *network);

// Simple implementation that uses docker command line instead of API
int docker_init(const char **networks, int network_count) {
    if (network_count <= 0) {
        return 0;
    }
    
    docker_network_names = malloc(sizeof(char *) * network_count);
    if (!docker_network_names) {
        perror("malloc");
        return -1;
    }
    
    for (int i = 0; i < network_count; i++) {
        docker_network_names[i] = strdup(networks[i]);
        if (!docker_network_names[i]) {
            perror("strdup");
            for (int j = 0; j < i; j++) {
                free((void *)docker_network_names[j]);
            }
            free(docker_network_names);
            docker_network_names = NULL;
            return -1;
        }
    }
    
    docker_network_count = network_count;
    
    // Refresh all networks initially
    for (int i = 0; i < docker_network_count; i++) {
        docker_refresh_network(docker_network_names[i]);
    }
    
    printf("Docker initialized with %d networks, found %d IPv6 addresses\n", 
           docker_network_count, docker_ip_count);
    
    return 0;
}

void docker_cleanup(void) {
    if (docker_network_names) {
        for (int i = 0; i < docker_network_count; i++) {
            free((void *)docker_network_names[i]);
        }
        free(docker_network_names);
        docker_network_names = NULL;
    }
    docker_network_count = 0;
    docker_ip_count = 0;
    docker_new_ip_count = 0;
    docker_new_ip_index = 0;
}

static int docker_refresh_network(const char *network) {
    FILE *fp;
    char cmd[512];
    char line[256];
    
    // Get IPv6 addresses from containers in this network
    snprintf(cmd, sizeof(cmd), 
             "docker network inspect %s --format='{{range .Containers}}{{.IPv6Address}}{{end}}' | "
             "tr -d '/' | grep -o '[0-9a-f:]\\+'", 
             network);
    
    fp = popen(cmd, "r");
    if (!fp) {
        perror("popen");
        return -1;
    }
    
    struct in6_addr old_ips[MAX_IPS];
    int old_ip_count = docker_ip_count;
    memcpy(old_ips, docker_ips, sizeof(struct in6_addr) * old_ip_count);
    
    // Clear existing IPs for this network
    docker_ip_count = 0;
    
    // Read IPv6 addresses
    while (fgets(line, sizeof(line), fp)) {
        // Remove newline
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        
        // Parse IPv6 address
        if (inet_pton(AF_INET6, line, &docker_ips[docker_ip_count]) == 1) {
            // Check if this is a new IP
            int is_new = 1;
            for (int i = 0; i < old_ip_count; i++) {
                if (memcmp(&docker_ips[docker_ip_count], &old_ips[i], sizeof(struct in6_addr)) == 0) {
                    is_new = 0;
                    break;
                }
            }
            
            if (is_new && docker_new_ip_count < MAX_IPS) {
                memcpy(&docker_new_ips[docker_new_ip_count], 
                       &docker_ips[docker_ip_count], 
                       sizeof(struct in6_addr));
                docker_new_ip_count++;
                
                char ip_str[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &docker_ips[docker_ip_count], ip_str, sizeof(ip_str));
                printf("New Docker IP found: %s\n", ip_str);
            }
            
            docker_ip_count++;
            if (docker_ip_count >= MAX_IPS) break;
        }
    }
    
    pclose(fp);
    return 0;
}

bool docker_contains_ip(const struct in6_addr *ip) {
    for (int i = 0; i < docker_ip_count; i++) {
        if (memcmp(ip, &docker_ips[i], sizeof(struct in6_addr)) == 0) {
            return true;
        }
    }
    return false;
}

int docker_poll_new_ip(struct in6_addr *new_ip) {
    // Refresh Docker networks occasionally
    static int refresh_counter = 0;
    refresh_counter++;
    if (refresh_counter >= 10) {
        refresh_counter = 0;
        for (int i = 0; i < docker_network_count; i++) {
            docker_refresh_network(docker_network_names[i]);
        }
    }
    
    // Check if we have new IPs to report
    if (docker_new_ip_index < docker_new_ip_count) {
        memcpy(new_ip, &docker_new_ips[docker_new_ip_index], sizeof(struct in6_addr));
        docker_new_ip_index++;
        return 1;
    }
    
    // Clear the new IP buffer if we've processed all of them
    if (docker_new_ip_index >= docker_new_ip_count) {
        docker_new_ip_count = 0;
        docker_new_ip_index = 0;
    }
    
    return 0;
}
