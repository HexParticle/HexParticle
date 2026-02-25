/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#include "ipv4_parser.h"
#include "tcp_parser.h"
#include "proto_node.h"
#include "udp_parser.h"
#include "ip.h"

#include <string.h>

ProtocolNode_t* parse_ipv4_packet(const uint8_t* stream) {
	IPV4Header_t* ip_header = malloc(sizeof(IPV4Header_t));

	ip_header->ver_ihl = 	stream[0];
	ip_header->dscp_ecn = 	stream[1];
	ip_header->len = 		stream[2] << 8 | 
							stream[3];
	ip_header->id = 		stream[4] << 8 | 
							stream[5];
	ip_header->flags_off = 	stream[6] << 8 | 
							stream[7];
	ip_header->ttl = 		stream[8];
	ip_header->proto = 		stream[9];
	ip_header->chk = 		stream[10] << 8 | 
							stream[11];

	memcpy(ip_header->src, stream + 12, 4);
	memcpy(ip_header->dst, stream + 16, 4);

	uint8_t ihl = ip_header->ver_ihl & 0x0F;
	
	ProtocolNode_t* ip_node = create_proto_node();
	ip_node->type = PROTO_IPV4;
	ip_node->hdr = ip_header;

	int skip_proto = 0; // do not skip the protocol

	if (ip_header->proto == IPPROTO_TCP) {
        const uint8_t* tcp_stream = stream + (ihl * 4);
		ip_node->next = parse_tcp_packet(tcp_stream);
	}
	else if (ip_header->proto == IPPROTO_UDP) {
        const uint8_t* udp_stream = stream + UDP_HEADER_LEN;
		ip_node->next = parse_udp_packet(udp_stream);
	}
	return ip_node;
}
