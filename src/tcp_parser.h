/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#ifndef TCP_PARSER_H
#define TCP_PARSER_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "hex.h"
#include "proto_node.h"

/**
 * TCP header
 */
typedef struct __attribute__((packed)) TCPHeader {
    uint16_t    sport;
    uint16_t    dport;
    uint32_t    seq;
    uint32_t    ack;
    uint8_t     off_res;
    uint8_t     flags;
    uint16_t    win;
    uint16_t    chk;
    uint16_t    urg;
    uint8_t     options[];
} TCPHeader_t;

HEX_P ProtocolNode_t* parse_tcp_packet(const uint8_t* stream);

#endif
