/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#include "arp_parser.h"

#include <string.h>

ProtocolNode_t* parse_arp_packet(const uint8_t* stream) {
	const size_t arp_header_size = sizeof(ARPHeader_t);

	ARPHeader_t* arp_hdr = malloc(arp_header_size);
	arp_hdr->htype = (stream[0] << 8) | stream[1];
    arp_hdr->ptype = (stream[2] << 8) | stream[3];
    arp_hdr->op    = (stream[6] << 8) | stream[7];

	memcpy(arp_hdr->sha, stream + 8,  6);  // Sender MAC
    memcpy(arp_hdr->spa, stream + 14, 4);  // Sender IP
    memcpy(arp_hdr->tha, stream + 18, 6);  // Target MAC
    memcpy(arp_hdr->tpa, stream + 24, 4);  // Target IP

	ProtocolNode_t* arp_node = create_proto_node();
	arp_node->type = PROTO_ARP;
	arp_node->hdr = arp_hdr;
	arp_node->hdr_len = arp_header_size;

	return arp_node;
}
