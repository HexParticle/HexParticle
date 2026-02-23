/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#ifndef ARP_PARSER_H
#define ARP_PARSER_H

#include "hex.h"
#include "proto_node.h"

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>

#define ARP_REQUEST		1 /* ARP request */
#define ARP_REPLY		2 /* ARP reply */

/// ARP packet header structure
typedef struct __attribute__((__packed__)) ARPHeader {
    uint16_t    htype;  // Hardware type (for e.g.: 1 for Ethernet)
    uint16_t    ptype;  // Protocol type (for: e.g.: 0x0800 for IPv4)
    uint8_t     hlen;   // Hardware address length (bytes) — 6 for MAC
    uint8_t     plen;   // Protocol address length (bytes) — 4 for IPv4
    uint16_t    op;     // Operation code: 1=Request, 2=Reply
    uint8_t     sha[6]; // Sender hardware address (MAC)
    uint8_t     spa[4]; // Sender protocol address (IPv4)
    uint8_t     tha[6]; // Target hardware address (MAC)
    uint8_t     tpa[4]; // Target protocol address (IPv4)
} ARPHeader_t;

/// Parse an ARP packet from a raw byte stream
/// @param stream Pointer to the raw packet bytes
/// @return ProtocolNode representing the parsed ARP packet
HEX_P ProtocolNode_t* parse_arp_packet(const uint8_t* stream);

#endif
