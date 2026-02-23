/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#ifndef ETHER_PARSER_H
#define ETHER_PARSER_H

#include <stdint.h>
#include <stdlib.h>

#include "proto_node.h"

// Ether types
#define ETHER_TYPE_IPV4 		0x0800
#define ETHER_TYPE_ARP 			0x0806
#define ETHER_TYPE_IPV6 		0x86DD
#define ETHER_TYPE_VLAN			0x8100

#define MAC_ADDR_LEN 			0x6 /* Standard MAC address length is 6 bytes */
#define ETHER_PAYLOAD_OFF 		0xE /* Standard Ethernet header is 14 bytes */

#define VLAN_ID(tci)   ((tci) & 0x0FFF)			/* VLAN identifier (VID) */
#define VLAN_PRI(tci)  (((tci) >> 13) & 0x07)	/* Priority code point */
#define VLAN_DEI(tci)  (((tci) >> 12) & 0x01)	/* Drop eligible indicator (DEI) */

#define MAX_VLAN_STACK 		4

/**
 * 802.1Q
 */
typedef struct __attribute__((packed)) VlanTag {
	uint16_t tpid; /* Tag protocol identifier */
	uint16_t tci;  /* Tag control information */
} VlanTag_t;

typedef struct {
    uint8_t  	src_mac[MAC_ADDR_LEN];
    uint8_t  	dst_mac[MAC_ADDR_LEN];
    uint16_t 	type;
    uint32_t 	len;

	// VLAN support
	int			vlan_count;
	VlanTag_t	vlans[MAX_VLAN_STACK];
} __attribute__((packed)) EtherHeader_t;

ProtocolNode_t* parse_ether_packet(const uint8_t* stream, size_t len);

#endif
