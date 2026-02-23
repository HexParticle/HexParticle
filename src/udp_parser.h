/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#ifndef UDP_PARSER_H
#define UDP_PARSER_H

#include <stdint.h>

#include "hex.h"
#include "proto_node.h"

#define UDP_HEADER_LEN		8 // 8-bytes

typedef struct UDPHeader {
	uint16_t	sport;	/* Source port */
	uint16_t	dport;	/* Destination port */
	uint16_t	length; /* Total length */
	uint16_t	cksum;  /* Checksum */
} UDPHeader_t;

HEX_P ProtocolNode_t* parse_udp_packet(const uint8_t* stream);

#endif
