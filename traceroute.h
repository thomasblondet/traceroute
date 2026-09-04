#ifndef TRACEROUTE_H
#define TRACEROUTE_H

#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>

typedef struct {
    int fd;
    char hostname[NI_MAXHOST];
    char ip[INET_ADDRSTRLEN];
    struct sockaddr_in addr;
    unsigned int ttl;
} Host;

#endif