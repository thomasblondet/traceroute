#include "traceroute.h"

static void fatal(const char *str) {
    fprintf(stderr, "traceroute: ");
    perror(str);
    exit(1);
}

static void hostname_resolution(Host *h) {
    const struct addrinfo hints = {
        .ai_flags = 0,
        .ai_family = AF_INET,
        .ai_socktype = 0,
        .ai_protocol = 0,
        .ai_addrlen = 0,
        .ai_addr = NULL,
    };

    struct addrinfo *res = NULL;
    const int ret = getaddrinfo(h->hostname, NULL, &hints, &res);
    if (ret != 0) {
        printf("ft_ping: cannot resolve %s: %s\n", h->hostname, gai_strerror(ret));
        exit(1);
    }

    const struct sockaddr_in *sin = (const struct sockaddr_in *)res->ai_addr;
    inet_ntop(AF_INET, &sin->sin_addr, h->ip, INET_ADDRSTRLEN);
    h->addr.sin_family = AF_INET;
    memcpy(&h->addr.sin_addr, &sin->sin_addr, sizeof(sin->sin_addr));

    freeaddrinfo(res);
}

int main(int argc, char *argv[]) {
    Host host = {0};

    (void)argc;
    memcpy(host.hostname, argv[1], strlen(argv[1]));
    hostname_resolution(&host);
    printf("%s %s\n", host.hostname, host.ip);
    return 0;
}