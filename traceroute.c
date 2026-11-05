#include <arpa/inet.h>
#include <errno.h>
#include <float.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define MAX_HOPS 64
#define QUERIES 3
#define WAIT_MS 1000
#define BASE_PORT 33434

typedef enum {
    RECV_ERROR,
    RECV_TIMEOUT,
    RECV_IGNORE,
    RECV_HOP,
    RECV_REACHED,
    RECV_UNREACHABLE
} RecvResult;

typedef struct {
    char name[NI_MAXHOST+1];
    char ip[INET_ADDRSTRLEN+1];
    struct sockaddr_in sa;
    int sendsock;
    int recvsock;
    uint16_t port;
    size_t ttl;
    struct in_addr responder;
} Host;

static void
usage(void)
{
    printf("usage: traceroute <hostname>\n");
    exit(1);
}

static void
fatal(const char *msg, int sendsock, int recvsock)
{
    int saved_errno = errno;

    fprintf(stderr, "traceroute: ");
    errno = saved_errno;
    perror(msg);
    if (sendsock >= 0)
        close(sendsock);
    if (recvsock >= 0)
        close(recvsock);
    exit(1);
}

static int
resolve_hostname(const char *name, char *ip, struct sockaddr_in *sa)
{
    struct addrinfo hints = {0}, *res = NULL;

    hints.ai_family = AF_INET;

    int ret = getaddrinfo(name, NULL, &hints, &res);
    if (ret)
        return ret;

    struct sockaddr_in *sin = (struct sockaddr_in *)res->ai_addr;
    *sa = *sin;

    if (!inet_ntop(AF_INET, &sin->sin_addr, ip, INET_ADDRSTRLEN)) {
        int saved_errno = errno;
        freeaddrinfo(res);
        errno = saved_errno;
        return EAI_SYSTEM;
    }
    freeaddrinfo(res);
    return 0;
}

static int
set_ttl(int fd, int ttl)
{
    return setsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
}

static void
init_sockets(Host *h)
{
	h->sendsock = socket(AF_INET, SOCK_DGRAM, 0);
	if (h->sendsock < 0)
		fatal("socket", h->sendsock, h->recvsock);

	struct sockaddr_in local = { .sin_family = AF_INET };
	if (bind(h->sendsock, (struct sockaddr *)&local, sizeof(local)) < 0)
		fatal("bind", h->sendsock, h->recvsock);
	socklen_t local_len = sizeof(local);
	if (getsockname(h->sendsock, (struct sockaddr *)&local, &local_len) < 0)
		fatal("getsockname", h->sendsock, h->recvsock);
	h->port = ntohs(local.sin_port);

	h->recvsock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (h->recvsock < 0)
		fatal("socket", h->sendsock, h->recvsock);

    struct timeval timeout = {
        .tv_sec = WAIT_MS / 1000,
        .tv_usec = (WAIT_MS % 1000) * 1000
    };
    if (setsockopt(h->recvsock, SOL_SOCKET, SO_RCVTIMEO,
            &timeout, sizeof(timeout)) < 0)
        fatal("setsockopt", h->sendsock, h->recvsock);
}

int
sendudp(Host *h)
{
    const char *s = "hello";
    ssize_t n;

    do {
        n = sendto(h->sendsock, s, strlen(s), 0, (struct sockaddr *)&h->sa, sizeof(h->sa));
    } while (n < 0 && errno == EINTR);

    return n < 0 ? -1 : 0;
}

RecvResult
recvicmp(Host *h)
{
    uint8_t buf[IP_MAXPACKET];
    struct ip *iphdr, *original_iphdr;
    struct icmp *icmphdr;
    struct udphdr *udphdr;
    size_t iphdrlen;
    ssize_t n;

    do {
        n = recvfrom(h->recvsock, buf, IP_MAXPACKET, 0, NULL, NULL);
    } while (n < 0 && errno == EINTR);

    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return RECV_TIMEOUT;
        return RECV_ERROR;
    }
    if ((size_t)n < sizeof(struct ip))
        return RECV_IGNORE;

    iphdr = (struct ip *)buf;
    iphdrlen = iphdr->ip_hl * 4;
    if (iphdr->ip_v != 4 || iphdr->ip_p != IPPROTO_ICMP ||
        iphdrlen < sizeof(struct ip) || (size_t)n < iphdrlen + ICMP_MINLEN)
        return RECV_IGNORE;

    icmphdr = (struct icmp *)(buf + iphdrlen);
    if (icmphdr->icmp_type != ICMP_TIMXCEED && icmphdr->icmp_type != ICMP_UNREACH)
        return RECV_IGNORE;

    size_t offset = iphdrlen + ICMP_MINLEN;
    if ((size_t)n - offset < sizeof(struct ip))
        return RECV_IGNORE;

    original_iphdr = (struct ip *)(buf + offset);
    iphdrlen = original_iphdr->ip_hl * 4;

    if (original_iphdr->ip_v != 4 || original_iphdr->ip_p != IPPROTO_UDP ||
        iphdrlen < sizeof(struct ip) ||
        (size_t)n - offset < iphdrlen + sizeof(struct udphdr))
        return RECV_IGNORE;

    udphdr = (struct udphdr *)(buf + offset + iphdrlen);
    if (ntohs(udphdr->uh_sport) != h->port ||
        udphdr->uh_dport != h->sa.sin_port ||
        original_iphdr->ip_dst.s_addr != h->sa.sin_addr.s_addr)
        return RECV_IGNORE;

    h->responder = iphdr->ip_src;

    if (icmphdr->icmp_type == ICMP_TIMXCEED)
        return icmphdr->icmp_code == ICMP_TIMXCEED_INTRANS ? RECV_HOP : RECV_IGNORE;

    if (icmphdr->icmp_code == ICMP_UNREACH_PORT &&
        iphdr->ip_src.s_addr == h->sa.sin_addr.s_addr)
        return RECV_REACHED;
    return RECV_UNREACHABLE;
}

static double
now_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
        fatal("clock_gettime", -1, -1);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1000000.0;
}

void
loop(Host *h)
{
    uint16_t dst_port = BASE_PORT;

    printf("traceroute to %s (%s), %d hops max\n", h->name, h->ip, MAX_HOPS);
    for (h->ttl = 1; h->ttl <= MAX_HOPS; h->ttl++) {
        int finished = 0;
        int ip_printed = 0;
        struct in_addr last_ip = {0};

        printf("%2zu", h->ttl);
        fflush(stdout);
        if (set_ttl(h->sendsock, (int)h->ttl) < 0)
            fatal("setsockopt", h->sendsock, h->recvsock);

        for (size_t query = 0; query < QUERIES; query++) {
            h->sa.sin_port = htons(dst_port++);
            double start = now_ms();
            RecvResult result;

            if (sendudp(h) < 0)
                fatal("sendto", h->sendsock, h->recvsock);

            do {
                result = recvicmp(h);
            } while (result == RECV_IGNORE);

            if (result == RECV_ERROR)
                fatal("recvfrom", h->sendsock, h->recvsock);

            if (result == RECV_TIMEOUT) {
                printf("  *");
            } else {
                double elapsed = now_ms() - start;
                if (!ip_printed || h->responder.s_addr != last_ip.s_addr) {
                    char addr[INET_ADDRSTRLEN];
                    if (!inet_ntop(AF_INET, &h->responder, addr, sizeof(addr)))
                        fatal("inet_ntop", h->sendsock, h->recvsock);
                    printf("  %s", addr);
                    last_ip = h->responder;
                    ip_printed = 1;
                }
                printf("  %.3f ms%s",
                    elapsed, result == RECV_UNREACHABLE ? " !unreachable" : "");
                if (result == RECV_REACHED || result == RECV_UNREACHABLE)
                    finished = 1;
            }
            fflush(stdout);
        }
        putchar('\n');
        if (finished)
            break;
    }
}

int
main(int argc, char *argv[])
{
    Host h = { .sendsock = -1, .recvsock = -1 };

    if (argc != 2)
        usage();

    if (strlen(argv[1]) >= sizeof(h.name)) {
        fprintf(stderr, "traceroute: hostname too long (maximum %zu characters)\n",
            sizeof(h.name) - 1);
        return 1;
    }
    strcpy(h.name, argv[1]);
    int ret = resolve_hostname(h.name, h.ip, &h.sa);
    if (ret == EAI_SYSTEM)
        fatal("resolve_hostname", -1, - 1);
    if (ret) {
        fprintf(stderr, "traceroute: %s: %s\n", h.name, gai_strerror(ret));
        return 1;
    }

    init_sockets(&h);
    loop(&h);
    close(h.sendsock);
    close(h.recvsock);

    return 0;
}
