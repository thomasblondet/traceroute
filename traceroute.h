#ifndef TRACEROUTE_H
#define TRACEROUTE_H

#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>

#define MAX_HOPS 64
#define NUM_QUERIES 3

typedef struct {
    int udpsock;
    int icmpsock;
    char hostname[NI_MAXHOST + 1];
    char ip[INET_ADDRSTRLEN + 1];
    struct sockaddr_in addr;
    unsigned int ttl;
} Host;

#endif
