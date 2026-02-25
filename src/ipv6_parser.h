/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#ifndef IPV6_PARSER_H
#define IPV6_PARSER_H

#include <stdint.h>

#include "proto_node.h"
#include "hex.h"
#include "ip.h"

#define IPV6_HEADER_LEN				40 /* 40-bytes */

#define IPV6_EXT_HOP_BY_HOP 		0
#define IPV6_EXT_ROUTING			43
#define IPV6_EXT_FRAGMENT			44
#define IPV6_EXT_AUTH_HDR			51 // Authentication Header
#define IPV6_EXT_ESP				50 // Encapsulating Security Payload
#define IPV6_EXT_DEST_OPTS			60 // Destination Options
#define IPV6_EXT_MOBILITY			135

/**
 * IPv6 extension header structure.
 */
typedef struct __attribute__((packed)) IPV6ExtHeader {
    uint8_t next_hdr; 		/* Next header */
    uint8_t hdr_ext_len; 	/* Header extension length */
} IPV6ExtHeader_t;

/**
 * IPv6 header structure.
 */
typedef struct __attribute__((packed)) IPV6Header {
	uint32_t 	ver_tc_fl; 				/* Version(4 bits), Traffic Class(6+2 bits), and Flow Label(20 bits) */
	uint16_t 	len;       				/* Payload length */
	uint8_t 	next_hdr;  				/* This field usually specifies the transport layer protocol used by a packet's payload. */
	uint8_t 	hop_limit; 				/* Replaces the time to live field in IPv4 */
	uint8_t 	src[IPV6_ADDR_LEN];   	/* Source address */
	uint8_t 	dst[IPV6_ADDR_LEN];   	/* Destination address */
} IPV6Header_t;

// sanity checks
_Static_assert(sizeof(IPV6Header_t) == 40, "IPV6Header_t's length must be 40 bytes");

HEX_P ProtocolNode_t* parse_ipv6_packet(const RawPacketStream_t* stream);

HEX_P inline uint8_t ipv6_version(const IPV6Header_t*);

HEX_P inline uint8_t ipv6_traffic_class(const IPV6Header_t*);

HEX_P inline uint32_t ipv6_flow_label(const IPV6Header_t*);

#endif
