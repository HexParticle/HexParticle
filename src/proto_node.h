/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#ifndef PROTO_NODE_H
#define PROTO_NODE_H

#include <stdint.h>

typedef enum ProtocolType {
    PROTO_ETH,
    PROTO_IPV4,
    PROTO_IPV6,
    PROTO_ARP,
    PROTO_TCP,
    PROTO_UDP,
    PROTO_RAW
} ProtocolType_t;

typedef struct ProtocolNode {
    enum ProtocolType 		type;
    void* 					hdr;
    uint32_t				hdr_len;
    struct ProtocolNode* 	next;
} ProtocolNode_t;

ProtocolNode_t* create_proto_node(void);

#endif
