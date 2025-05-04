/*
 * Copyright (c) 2023 Lucas Kafarski
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the conditions of the BSD 3-Clause
 * License are met.
 */

#include "hostinfo.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#define BUFFER_SIZE 4096

static int get_interface_mac(const char *interface, uint8_t *mac) {
    struct ifreq ifr;
    int sockfd;
    
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }
    
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl");
        close(sockfd);
        return -1;
    }
    
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(sockfd);
    
    return 0;
}

static int get_default_gateway_ipv6(const char *interface, struct in6_addr *gateway) {
    int sockfd;
    int if_index;
    struct {
        struct nlmsghdr nlh;
        struct rtmsg rtm;
        char buf[BUFFER_SIZE];
    } req;
    
    struct sockaddr_nl sa;
    ssize_t rlen;
    char buf[BUFFER_SIZE];
    struct nlmsghdr *nlh;
    struct rtmsg *rtm;
    struct rtattr *rta;
    int rtl;
    
    // Get interface index
    if_index = if_nametoindex(interface);
    if (if_index == 0) {
        perror("if_nametoindex");
        return -1;
    }
    
    // Open netlink socket
    sockfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }
    
    // Prepare request
    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.nlh.nlmsg_type = RTM_GETROUTE;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.rtm.rtm_family = AF_INET6;
    req.rtm.rtm_table = RT_TABLE_MAIN;
    
    // Send request
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    
    if (sendto(sockfd, &req, req.nlh.nlmsg_len, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("sendto");
        close(sockfd);
        return -1;
    }
    
    // Receive response
    while ((rlen = recv(sockfd, buf, sizeof(buf), 0)) > 0) {
        nlh = (struct nlmsghdr *)buf;
        
        for (; NLMSG_OK(nlh, rlen); nlh = NLMSG_NEXT(nlh, rlen)) {
            if (nlh->nlmsg_type == NLMSG_DONE) {
                close(sockfd);
                return -1; // Gateway not found
            }
            
            if (nlh->nlmsg_type == NLMSG_ERROR) {
                perror("netlink error");
                close(sockfd);
                return -1;
            }
            
            rtm = (struct rtmsg *)NLMSG_DATA(nlh);
            if (rtm->rtm_family != AF_INET6) {
                continue;
            }
            
            // Only interested in default route
            if (rtm->rtm_dst_len != 0) {
                continue;
            }
            
            // Check if it's for our interface
            int oif = 0;
            struct in6_addr *gw = NULL;
            
            rta = RTM_RTA(rtm);
            rtl = RTM_PAYLOAD(nlh);
            for (; RTA_OK(rta, rtl); rta = RTA_NEXT(rta, rtl)) {
                switch (rta->rta_type) {
                    case RTA_OIF:
                        oif = *(int *)RTA_DATA(rta);
                        break;
                    case RTA_GATEWAY:
                        gw = (struct in6_addr *)RTA_DATA(rta);
                        break;
                }
            }
            
            if (oif == if_index && gw != NULL) {
                memcpy(gateway, gw, sizeof(struct in6_addr));
                close(sockfd);
                return 0;
            }
        }
    }
    
    close(sockfd);
    return -1;
}

int hostinfo_gather(const char *interface, host_info_t *hi) {
    memset(hi, 0, sizeof(host_info_t));
    
    printf("Gathering host information for interface %s...\n", interface);
    
    // Get MAC address
    if (get_interface_mac(interface, hi->host_mac) < 0) {
        fprintf(stderr, "Failed to get MAC address for interface %s\n", interface);
        return -1;
    }
    
    printf("MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n", 
           hi->host_mac[0], hi->host_mac[1], hi->host_mac[2], 
           hi->host_mac[3], hi->host_mac[4], hi->host_mac[5]);
    
    // Get default gateway
    if (get_default_gateway_ipv6(interface, &hi->gateway_ip) < 0) {
        fprintf(stderr, "Warning: Failed to get IPv6 default gateway for interface %s\n", interface);
        hi->has_gateway = 0;
    } else {
        hi->has_gateway = 1;
        char gw_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &hi->gateway_ip, gw_str, sizeof(gw_str));
        printf("IPv6 gateway: %s\n", gw_str);
    }
    
    return 0;
}

int hostinfo_ensure_gateway_neigh(const char *interface, host_info_t *hi) {
    if (!hi->has_gateway) {
        return 0;
    }
    
    char gw_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &hi->gateway_ip, gw_str, sizeof(gw_str));
    
    // Ping the gateway to trigger neighbor discovery
    char cmd[256];
    sprintf(cmd, "/usr/bin/ping -c 1 %s > /dev/null 2>&1", gw_str);
    int ret = system(cmd);  // Store return value to avoid warning
    if (ret != 0) {
        printf("Warning: ping to gateway %s failed with code %d\n", gw_str, ret);
    }
    
    // Use netlink to set the neighbor entry to NOARP
    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) {
        perror("Failed to open netlink socket");
        return -1;
    }
    
    // Setup request buffer
    char buf[NLMSG_SPACE(sizeof(struct ndmsg)) + RTA_SPACE(sizeof(struct in6_addr))];
    memset(buf, 0, sizeof(buf));
    
    // Setup netlink header
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
    nlh->nlmsg_type = RTM_NEWNEIGH;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_REPLACE;
    nlh->nlmsg_seq = 1;
    nlh->nlmsg_pid = getpid();
    
    // Setup ndmsg structure
    struct ndmsg *ndm = NLMSG_DATA(nlh);
    ndm->ndm_family = AF_INET6;
    ndm->ndm_ifindex = if_nametoindex(interface);
    ndm->ndm_state = NUD_PERMANENT;
    ndm->ndm_flags = NTF_PROXY;  // Set NTF_PROXY flag to have us respond
    ndm->ndm_type = 0;
    
    // Add destination address attribute
    struct rtattr *rta = (struct rtattr *)(((char *)ndm) + sizeof(struct ndmsg));
    rta->rta_type = NDA_DST;
    rta->rta_len = RTA_LENGTH(sizeof(struct in6_addr));
    memcpy(RTA_DATA(rta), &hi->gateway_ip, sizeof(struct in6_addr));
    
    // Update nlh->nlmsg_len to include the attribute
    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_LENGTH(sizeof(struct in6_addr));
    
    // Send the message
    struct sockaddr_nl nladdr;
    memset(&nladdr, 0, sizeof(nladdr));
    nladdr.nl_family = AF_NETLINK;
    
    struct iovec iov = { buf, nlh->nlmsg_len };
    struct msghdr msg = {
        &nladdr, sizeof(nladdr),
        &iov, 1,
        NULL, 0,
        0
    };
    
    if (sendmsg(sock, &msg, 0) < 0) {
        perror("Failed to send netlink message");
        close(sock);
        return -1;
    }
    
    printf("Set gateway neighbor entry to NOARP/PROXY for %s\n", gw_str);
    close(sock);
    
    return 0;
}
