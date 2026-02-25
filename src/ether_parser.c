/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#include "proto_node.h"
#include "ether_parser.h"
#include "ipv4_parser.h"
#include "arp_parser.h"
#include "ipv6_parser.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static int parse_vlan_tags(EtherHeader_t* const eth_header, const uint8_t* stream, size_t len);

ProtocolNode_t* parse_ether_packet(const uint8_t* stream, size_t len) {
	EtherHeader_t* eth_header = malloc(sizeof(EtherHeader_t));

	if (eth_header == NULL) {
		fprintf(stderr, "Failed to allocate memory for Ethernet header\n");
		return NULL;
	}

    memcpy(eth_header->dst_mac, stream, MAC_ADDR_LEN);
    memcpy(eth_header->src_mac, stream + 6, MAC_ADDR_LEN);

    eth_header->len = len;

	int payload_off = parse_vlan_tags(eth_header, stream, len);

	if (payload_off < 0) {
		free(eth_header);
		fflush(stderr);
		return NULL;
	}

	ProtocolNode_t* ether_node = create_proto_node();
	ether_node->type = PROTO_ETH;
	ether_node->hdr = eth_header;
    
    if (eth_header->type <= 1500) {
        fprintf(stderr, "Skipping IEEE 802.3 frame (unsupported).\n");
		fflush(stderr);
		free(eth_header);
		free(ether_node);
        return NULL;
    }

	if (eth_header->type == ETHER_TYPE_IPV4) {
		ether_node->next = parse_ipv4_packet((stream + payload_off));
	}
	else if (eth_header->type == ETHER_TYPE_ARP) {
		ether_node->next = parse_arp_packet((stream + payload_off));
	}
	else if (eth_header->type == ETHER_TYPE_IPV6) {
		RawPacketStream_t raw_stream = { .stream = stream + payload_off, .length = len };
		ether_node->next = parse_ipv6_packet(&raw_stream);
	}

	return ether_node;
}

static int parse_vlan_tags(EtherHeader_t* eth_header, const uint8_t* stream, size_t len) {
	int payload_off = ETHER_PAYLOAD_OFF;

	// first parse the ether type
	eth_header->type = (stream[12] << 8) | stream[13];
	eth_header->vlan_count = 0;

	while (eth_header->type == ETHER_TYPE_VLAN) {
		if (eth_header->vlan_count >= MAX_VLAN_STACK) {
			fprintf(stderr, "Warning: VLAN stack overflow.\n");
			return -1;
		};

        if (len < payload_off + 4) {
            fprintf(stderr, "Malformed packet.\n");
            return -1;
        }

		VlanTag_t tag = {
			.tpid = ETHER_TYPE_VLAN,
			.tci = (stream[payload_off] << 8) | (stream[payload_off + 1])
		};

		eth_header->vlans[eth_header->vlan_count] = tag;
        eth_header->type = 
			((uint16_t) stream[payload_off + 2] << 8) | 
			((uint16_t) stream[payload_off + 3]);

        payload_off += 4;
		eth_header->vlan_count += 1;
    }
	return payload_off;
}
