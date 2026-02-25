/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#include <stdlib.h>
#include <stdio.h>

#include "proto_node.h"

ProtocolNode_t* create_proto_node(void) {
	ProtocolNode_t* node = malloc(sizeof(ProtocolNode_t));
	if (node) {
		node->hdr 	= NULL;
		node->next 	= NULL;
		node->type 	= -1;
	}
	else {
		fprintf(stderr, "malloc failed");
		exit(EXIT_FAILURE);
	}
	return node;
}
