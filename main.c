#include "traceroute.h"

static int g_reached = 0;

static void fatal(const char *str) {
    fprintf(stderr, "traceroute: ");
    perror(str);
    exit(1);
}

static void hostname_resolution(Host *h) {
    const struct addrinfo hints = {
        .ai_flags = 0,
        .ai_family = AF_INET,
        .ai_socktype = SOCK_DGRAM,
        .ai_protocol = 0,
        .ai_addrlen = 0,
        .ai_addr = NULL,
    };

    struct addrinfo *res = NULL;
    const int ret = getaddrinfo(h->hostname, NULL, &hints, &res);
    if (ret != 0) {
        printf("traceroute: cannot resolve %s: %s\n", h->hostname, gai_strerror(ret));
        exit(1);
    }

    const struct sockaddr_in *sin = (const struct sockaddr_in *)res->ai_addr;
    inet_ntop(AF_INET, &sin->sin_addr, h->ip, INET_ADDRSTRLEN);
    h->addr.sin_family = AF_INET;
	h->addr.sin_port = htons(33434);
    memcpy(&h->addr.sin_addr, &sin->sin_addr, sizeof(sin->sin_addr));

    freeaddrinfo(res);
}

void send_packet(Host *h) {
	const char *message = "hello world";

	if (sendto(h->udpsock, message, sizeof(message), 0, (struct sockaddr *)&h->addr,
		sizeof(struct sockaddr_in)) < 0)
		fatal("sendto");
}

void parse_packet(uint8_t *buf) {
	struct ip *outer_ip = (struct ip *)buf;
	size_t outer_ip_len = outer_ip->ip_hl * 4;
	struct icmp *outer_icmp = (struct icmp *)(buf + outer_ip_len);

	if (outer_icmp->icmp_type != ICMP_UNREACH || outer_icmp->icmp_code != ICMP_UNREACH_PORT)
		return;

	struct ip *inner_ip = (struct ip *)(buf + outer_ip_len + ICMP_MINLEN);
	struct udphdr *inner_udp = (struct udphdr *)(buf + outer_ip_len + ICMP_MINLEN
			+ (inner_ip->ip_hl * 4));

	// wrong packet
	if (ntohs(inner_udp->uh_dport) != 33434)
		return;

	g_reached = 1;
}

double time_diff(struct timeval *start, struct timeval *end) {
	return ((end->tv_sec * 1000.0) + (end->tv_usec / 1000.0))
		- ((start->tv_sec * 1000.0) + (start->tv_usec / 1000.0));
}

void get_response(Host *h, struct timeval *start_time, size_t nquery) {
	uint8_t buf[IP_MAXPACKET];

	struct sockaddr_in from;
	socklen_t len = sizeof(from);
	ssize_t n = recvfrom(h->icmpsock, buf, IP_MAXPACKET, 0, (struct sockaddr *)&from, &len);
	if (n < 0) {
		if (errno == EWOULDBLOCK || errno == EAGAIN)
			fprintf(stdout, "  *%c", nquery == NUM_QUERIES - 1 ? '\n' : ' ');
		else
			fatal("recvfrom");
		return;
	}

	struct timeval end_time;
	gettimeofday(&end_time, NULL);

	// get the hop (router) ip address
	char hop[INET_ADDRSTRLEN + 1] = {0};
	if (getnameinfo((struct sockaddr *)&from, len, hop, INET_ADDRSTRLEN, NULL, 0, NI_NUMERICHOST) != 0)
		snprintf(hop, 2, "?");

	if (nquery == 0)
		fprintf(stdout, "  %s ", hop);

	fprintf(stdout, " %.3f ms%c", time_diff(start_time, &end_time),
			nquery == NUM_QUERIES - 1 ? '\n' : ' ');
	parse_packet(buf);
}

void init_socket(Host *h) {
	h->udpsock = socket(AF_INET, SOCK_DGRAM, 0);
	if (h->udpsock < 0)
		fatal("socket");

	h->icmpsock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (h->icmpsock < 0)
		fatal("socket");

	struct timeval tv = {3, 0};
	if (setsockopt(h->icmpsock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
		fatal("setsockopt");
}

void trace_route(Host *h) {
	init_socket(h);

	fprintf(stdout, "traceroute to %s (%s), %d hops max, 40 byte packets\n",
			h->hostname, h->ip, MAX_HOPS);

	while (h->ttl < MAX_HOPS) {
		fprintf(stdout, "%2d", h->ttl);
		if (setsockopt(h->udpsock, IPPROTO_IP, IP_TTL, &h->ttl, sizeof(h->ttl)) < 0)
			fatal("setsockopt");

		for (size_t i = 0; i < NUM_QUERIES; i++) {
			struct timeval start_time;
			gettimeofday(&start_time, NULL);

			send_packet(h);
			get_response(h, &start_time, i);

			if (g_reached == 1 && i == NUM_QUERIES - 1)
				return;
		}
		h->ttl++;
	}
}

int main(int argc, char *argv[]) {
    Host h = {
		.udpsock = -1,
		.icmpsock = -1,
		.hostname = {0},	
		.ip = {0},
		.addr = {0},
		.ttl = 1
    };
	
	if (argc != 2) {
		fprintf(stderr, "Usage: ./traceroute hostname\n");
		return 1;
	}

	memcpy(h.hostname, argv[1], strlen(argv[1]));

    hostname_resolution(&h);
	trace_route(&h);

	close(h.udpsock);
	close(h.icmpsock);
    return 0;
}
