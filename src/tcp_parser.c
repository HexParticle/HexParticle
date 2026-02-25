/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#include "tcp_parser.h"

#include <string.h>

ProtocolNode_t* parse_tcp_packet(const uint8_t* stream) {
    TCPHeader_t* tcp_header = malloc(sizeof(TCPHeader_t));
	memcpy(tcp_header, stream, sizeof(TCPHeader_t));

	ProtocolNode_t* tcp_node = create_proto_node();
	tcp_node->type = PROTO_TCP;
	tcp_node->hdr = tcp_header;

    return tcp_node;
}
