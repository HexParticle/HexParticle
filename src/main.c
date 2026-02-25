/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#include "hex.h"
#include "ether_parser.h"
#include "ipv4_parser.h"
#include "ipv6_parser.h"
#include "tcp_parser.h"
#include "udp_parser.h"
#include "arp_parser.h"

#include <stdlib.h>

static void mac_to_string(const uint8_t mac[MAC_ADDR_LEN], char *out) {
    sprintf(out, "%02X:%02X:%02X:%02X:%02X:%02X",
            mac[0], mac[1], mac[2],
            mac[3], mac[4], mac[5]);
}

static void dump_vlan_tags(const VlanTag_t* tags, int count) {
	for (int i = 0; i < count; i++) {
		const VlanTag_t tag = tags[i];
		printf("   TPID: %d\n", tag.tpid);
		printf("   TCI: %d\n", tag.tci);
	}
}

static void dump_ether_header(const EtherHeader_t* header) {
    if (header == NULL) {
        printf("ETHER NULL\n");
        return;
    }

    char src[18];
    char dst[18];

    mac_to_string(header->src_mac, src);
    mac_to_string(header->dst_mac, dst);

    printf("Ethernet(FROM %s TO %s)\n", src, dst);

	if (header->vlan_count > 0) {
		dump_vlan_tags(header->vlans, header->vlan_count);
	}
}

static void dump_ipv6_header(const IPV6Header_t* header) {
	if (header == NULL) {
        printf("IPv6 NULL\n");
        return;
	}

	printf("  IPv6(FROM %d.%d.%d.%d TO %d.%d.%d.%d)\n", 
			header->src[0],
			header->src[1],
			header->src[2],
			header->src[3],
			header->dst[0],
			header->dst[1],
			header->dst[2],
			header->dst[3]
	);
}

static void dump_ipv4_header(const IPV4Header_t* header) {
	if (header == NULL) {
        printf("IPv4 NULL\n");
        return;
	}

	printf("  IPv4(FROM %d.%d.%d.%d TO %d.%d.%d.%d)\n", 
			header->src[0],
			header->src[1],
			header->src[2],
			header->src[3],
			header->dst[0],
			header->dst[1],
			header->dst[2],
			header->dst[3]
	);
}

static void dump_arp_header(const ARPHeader_t* header) {
	if (header == NULL) {
        printf("ARP NULL\n");
        return;
	}

    char source[18];
    mac_to_string(header->sha, source);

	char target[18];
	mac_to_string(header->tha, target);

	if (header->op == ARP_REQUEST) {
		printf("  ARP(Who has %d.%d.%d.%d? Tell %s.)\n", 
			header->tpa[0],
			header->tpa[1],
			header->tpa[2],
			header->tpa[3],
			source
		);
	}
	else if (header->op == ARP_REPLY) {
		printf("  ARP(%s has %d.%d.%d.%d.)\n", 
			target, 
			header->tpa[0],
			header->tpa[1],
			header->tpa[2],
			header->tpa[3]
		);
	}
}

static void dump_tcp_header(const TCPHeader_t* header) {
	if (header == NULL) {
		printf("TCP NULL\n");
		return;
	}

	printf("    TCP(FROM %d TO %d)", header->sport, header->dport);
}

static void dump_udp_header(const UDPHeader_t* header) {
	if (header == NULL) {
		printf("UDP NULL");
		return;
	}

	printf("    UDP(FROM %d TO %d)", header->sport, header->dport);
}

static void dump_node(ProtocolNode_t* node) {
	ProtocolNode_t* current_node = node;
	
	while (current_node != NULL) {
		if (current_node->type == PROTO_ETH) {
			EtherHeader_t* eth_hdr = (EtherHeader_t*) current_node->hdr;
			dump_ether_header(eth_hdr);
		}
		else if (current_node->type == PROTO_IPV4) {
			IPV4Header_t* ip_hdr = (IPV4Header_t*) current_node->hdr;
			dump_ipv4_header(ip_hdr);
		}
		else if (current_node->type == PROTO_TCP) {
			TCPHeader_t* tcp_hdr = (TCPHeader_t*) current_node->hdr;
			dump_tcp_header(tcp_hdr);
		}
		else if (current_node->type == PROTO_UDP) {
			UDPHeader_t* udp_hdr = (UDPHeader_t*) current_node->hdr;
			dump_udp_header(udp_hdr);
		}
		else if (current_node->type == PROTO_IPV6) {
			IPV6Header_t* ipv6 = (IPV6Header_t*) current_node->hdr;
			dump_ipv6_header(ipv6);
		}

		current_node = current_node->next;
	}
	printf("\n");
}

#ifdef RUN_MAIN
int main(int argc, char** argv) {
	HexInstnace_t instance = create_hex_instance("en0");

	while (1) {
		ProtocolNode_t* result = read_next_packet(&instance);
		if (result != NULL) {
			dump_node(result);
			free_packet(result);
		}
	}

	free_hex_instance(&instance);
}

#endif
