/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#ifndef IPV4_PARSER_H
#define IPV4_PARSER_H

#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <stdio.h>

#include "proto_node.h"
#include "hex.h"
#include "ip.h"

/**
 * IPv4 header
 */
typedef struct __attribute__((packed)) IPV4Header {
    uint8_t     ver_ihl;			/* Version and Internet Header Length */
    uint8_t     dscp_ecn;
    uint16_t    len;
    uint16_t    id;
    uint16_t    flags_off;
    uint8_t     ttl;
    uint8_t     proto;
    uint16_t    chk;
    uint8_t     src[IPV4_ADDR_LEN]; /* Source IPv4 address */
    uint8_t     dst[IPV4_ADDR_LEN]; /* Destination IPv4 address */
} IPV4Header_t;

// sanity checks
_Static_assert(sizeof(IPV4Header_t) == 20, "IPV4Header_t's length must be 20 bytes");

#define IPV4_PROTOCOL_NAME_IPV4_ICMP        "ICMP(Internet Control Message Protocol)"
#define IPV4_PROTOCOL_NAME_IPV4_IGMP        "ICMP(Internet Group Management Protocol)"
#define IPV4_PROTOCOL_NAME_IPV4_TCP         "TCP(Transmission Control Protocol)"
#define IPV4_PROTOCOL_NAME_IPV4_UDP         "UDP(User Datagram Protocol)"
#define IPV4_PROTOCOL_NAME_IPV4_IPV6_ROUTE  "IPv6-Route(Routing Header for IPv6)"
#define IPV4_PROTOCOL_NAME_IPV4_DSR         "DSR(Dynamic Source Routing Protocol)"
#define IPV4_PROTOCOL_NAME_IPV4_SWIPE       "SwIPe(Swipe IP Security Protocol)"
#define IPV4_PROTOCOL_NAME_IPV4_TLSP        "TLSP(Transport Layer Security Protocol)"
#define IPV4_PROTOCOL_NAME_IPV4_SKIP        "SKIP(Simple Key Management for IP)"
#define IPV4_PROTOCOL_NAME_IPV4_SAT_EXPAK   "SAT-EXPAK(SATNET and Backroom EXPAK)"
#define IPV4_PROTOCOL_NAME_IPV4_EIGRP       "EIGRP(Enhanced Interior Gateway Routing Protocol)"
#define IPV4_PROTOCOL_NAME_IPV4_OSPF        "OSPF(Open Shorted Path First)"
#define IPV4_PROTOCOL_NAME_IPV4_L2TP        "L2TP(Layer 2 Tunneling Protocol version 3)"

#define IPV4_PROTOCOL_LIST  \
    X(IPV4_ICMP, IPV4_PROTOCOL_NAME_IPV4_ICMP) \
    X(IPV4_IGMP, IPV4_PROTOCOL_NAME_IPV4_IGMP) \
    X(IPV4_TCP, IPV4_PROTOCOL_NAME_IPV4_TCP) \
    X(IPV4_UDP, IPV4_PROTOCOL_NAME_IPV4_UDP) \
    X(IPV4_IPV6_ROUTE, IPV4_PROTOCOL_NAME_IPV4_IPV6_ROUTE) \
    X(IPV4_DSR, IPV4_PROTOCOL_NAME_IPV4_DSR) \
    X(IPV4_SWIPE, IPV4_PROTOCOL_NAME_IPV4_SWIPE) \
    X(IPV4_TLSP, IPV4_PROTOCOL_NAME_IPV4_TLSP) \
    X(IPV4_SKIP, IPV4_PROTOCOL_NAME_IPV4_SKIP) \
    X(IPV4_SAT_EXPAK, IPV4_PROTOCOL_NAME_IPV4_SAT_EXPAK) \
    X(IPV4_EIGRP, IPV4_PROTOCOL_NAME_IPV4_EIGRP) \
    X(IPV4_OSPF, IPV4_PROTOCOL_NAME_IPV4_OSPF) \


#define IPV4_PROTOCOL_NAME(code) IPV4_PROTOCOL_NAME_##code

/// Parse an IPv4 packet from a raw byte stream
/// @param stream Pointer to the raw packet bytes
/// @return ProtocolNode representing the parsed IPv4 packet
HEX_P ProtocolNode_t* parse_ipv4_packet(const uint8_t* stream);

HEX_P char* ipv4_proto_name(uint16_t proto);

#endif
