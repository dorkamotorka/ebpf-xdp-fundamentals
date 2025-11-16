//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include "parse_helpers.h"

SEC("xdp") 
int xdp_program(struct xdp_md *ctx) {
	void *data_end = (void *)(unsigned long long)ctx->data_end;
	void *data = (void *)(unsigned long long)ctx->data;
	struct hdr_cursor nh;
	nh.pos = data;

	int ip_type;
	// Parse Ethernet header
	struct ethhdr *eth;
	int eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == bpf_htons(ETH_P_IP)) { 
		bpf_printk("We have captured an IPv4 packet");
		struct iphdr *ip;
		// Parse IPv4 header
		ip_type = parse_iphdr(&nh, data_end, &ip);
		if ((void*)(ip + 1) > data_end) {
			goto out;
		}
		__u32 src = bpf_ntohl(ip->saddr);
		__u32 dst = bpf_ntohl(ip->daddr);

		bpf_printk("IPv4 src: %d.%d.%d.%d",
		    (src >> 24) & 0xFF,
		    (src >> 16) & 0xFF,
		    (src >> 8)  & 0xFF,
		    src & 0xFF);

		bpf_printk("IPv4 dst: %d.%d.%d.%d",
		    (dst >> 24) & 0xFF,
		    (dst >> 16) & 0xFF,
		    (dst >> 8)  & 0xFF,
		    dst & 0xFF);

		if (ip_type == IPPROTO_ICMP) {
			bpf_printk("We have captured an ICMP packet");
			// Parse ICMP header
			struct icmphdr *icmp;
			int icmp_type = parse_icmphdr(&nh, data_end, &icmp);
			if ((void*)(icmp + 1) > data_end) {
				goto out;
			}

			bpf_printk("Type: %d", icmp->type);
			bpf_printk("Code: %d", icmp->code);
			if (icmp->type == ICMP_ECHO || icmp->type == ICMP_ECHOREPLY) {
			    bpf_printk("Echo id=%d seq=%d\n",
				bpf_ntohs(icmp->un.echo.id),
				bpf_ntohs(icmp->un.echo.sequence));
			}
			goto out;
		}
	} else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		bpf_printk("We have captured an IPv6 packet");
		struct ipv6hdr *ipv6;
		// Parse IPv6 header
		ip_type = parse_ip6hdr(&nh, data_end, &ipv6);
		if ((void *)(ipv6 + 1) > data_end) {
			goto out;
		}

		// Print as 4x32-bit chunks (hex)
		bpf_printk("IPv6 src: %x:%x:%x:%x:%x:%x:%x:%x",
			bpf_ntohs(ipv6->saddr.in6_u.u6_addr16[0]),
			bpf_ntohs(ipv6->saddr.in6_u.u6_addr16[1]),
			bpf_ntohs(ipv6->saddr.in6_u.u6_addr16[2]),
			bpf_ntohs(ipv6->saddr.in6_u.u6_addr16[3]),
			bpf_ntohs(ipv6->saddr.in6_u.u6_addr16[4]),
			bpf_ntohs(ipv6->saddr.in6_u.u6_addr16[5]),
			bpf_ntohs(ipv6->saddr.in6_u.u6_addr16[6]),
			bpf_ntohs(ipv6->saddr.in6_u.u6_addr16[7]));

		bpf_printk("IPv6 dst: %x:%x:%x:%x:%x:%x:%x:%x",
			bpf_ntohs(ipv6->daddr.in6_u.u6_addr16[0]),
			bpf_ntohs(ipv6->daddr.in6_u.u6_addr16[1]),
			bpf_ntohs(ipv6->daddr.in6_u.u6_addr16[2]),
			bpf_ntohs(ipv6->daddr.in6_u.u6_addr16[3]),
			bpf_ntohs(ipv6->daddr.in6_u.u6_addr16[4]),
			bpf_ntohs(ipv6->daddr.in6_u.u6_addr16[5]),
			bpf_ntohs(ipv6->daddr.in6_u.u6_addr16[6]),
			bpf_ntohs(ipv6->daddr.in6_u.u6_addr16[7]));

		if (ip_type == IPPROTO_ICMPV6) {
			bpf_printk("We have captured an ICMP packet");
			struct icmp6hdr *icmp6;
			// Parse ICMP header
			int icmp6_type = parse_icmp6hdr(&nh, data_end, &icmp6);
			if ((void*)(icmp6 + 1) > data_end) {
				goto out;
			}

			bpf_printk("Type: %d", icmp6->icmp6_type);
			bpf_printk("Code: %d", icmp6->icmp6_code);
			if (icmp6->icmp6_type == ICMPV6_ECHO_REQUEST || icmp6->icmp6_type == ICMPV6_ECHO_REPLY) {
			    bpf_printk("Echo id=%d seq=%d\n",
				bpf_ntohs(icmp6->icmp6_dataun.u_echo.identifier),
				bpf_ntohs(icmp6->icmp6_dataun.u_echo.sequence));
			}
			goto out;
		}
	} else {
		// Default action, pass it up the GNU/Linux network stack to be handled
		return XDP_PASS;
	}

	if (ip_type == IPPROTO_TCP) {
		bpf_printk("We have captured a TCP packet");
		struct tcphdr *tcp;
		// Parse TCP header
		int tcp_type = parse_tcphdr(&nh, data_end, &tcp);
		if ((void*)(tcp + 1) > data_end) {
			goto out;
		}

		bpf_printk("Source port: %d", bpf_ntohs(tcp->source));
		bpf_printk("Destination port: %d", bpf_ntohs(tcp->dest));
		bpf_printk("Sequence number: %d", bpf_ntohs(tcp->seq));
		bpf_printk("Acknowledgment number: %d", bpf_ntohs(tcp->ack_seq));
		bpf_printk("Flags: SYN=%d ACK=%d FIN=%d RST=%d PSH=%d URG=%d ECE=%d CWR=%d",
        		tcp->syn, tcp->ack, tcp->fin, tcp->rst, tcp->psh, tcp->urg, tcp->ece, tcp->cwr);
	} else if (ip_type == IPPROTO_UDP) {
		bpf_printk("We have captured a UDP packet");
		// Parse UDP header
		struct udphdr *udp;
		int udp_type = parse_udphdr(&nh, data_end, &udp);
		if ((void*)(udp + 1) > data_end) {
			goto out;
		}

		bpf_printk("Source port: %d", bpf_ntohs(udp->source));
		bpf_printk("Destination port: %d", bpf_ntohs(udp->dest));
		bpf_printk("Length of the UDP datagram: %d", bpf_ntohs(udp->len));
		bpf_printk("Checksum for error detection: %d", bpf_ntohs(udp->check));
	}

out:
	bpf_printk("============================================\n\n"); // For structured output logging
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
