/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#include "udp_parser.h"

#include <string.h>
#include <stdlib.h>

ProtocolNode_t* parse_udp_packet(const uint8_t* stream) {
	UDPHeader_t* udp_hdr = malloc(sizeof(UDPHeader_t));
	memcpy(udp_hdr, stream, sizeof(UDPHeader_t));

	ProtocolNode_t* udp_node = create_proto_node();
	udp_node->hdr = udp_hdr;
	udp_node->type = PROTO_UDP;
	udp_node->hdr_len = UDP_HEADER_LEN;

	return udp_node;
}