/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#ifndef DNS_PARSER_H
#define DNS_PARSER_H

#include "hex.h"
#include "proto_node.h"

HEX_P ProtocolNode_t* parse_dns_packet(const RawPacketStream_t*);

#endif
