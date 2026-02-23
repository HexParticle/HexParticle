/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#include <pcap.h>
#include "proto_node.h"

/* Macro for symbol visibility, currently empty */
#define HEX_P

#define HEX_OUT_BUF_SIZE 4096

#ifndef HEX_PARTICLE_ANALYZER_H
#define HEX_PARTICLE_ANALYZER_H

/**
 * @struct HexInstance_t
 * @brief Container for the libpcap session handle.
 */
typedef struct _HexInstnace {
    pcap_t* 	handle;	/* libpcap session handle */
} HexInstnace_t;

typedef struct _RawPacketStream {
	uint8_t* 	stream;
	size_t		length;
} RawPacketStream_t;

/**
 * @brief Initializes a live capture session on the specified network device.
 * @param device The name of the interface (e.g., "eth0").
 * @return A HexInstnace_t structure containing the active pcap handle.
 * @note This function will terminate the process if the device cannot be opened.
 */
HEX_P HexInstnace_t create_hex_instance(const char* device);

/**
 * @brief Closes the pcap handle and releases associated instance memory.
 * @param handle Pointer to the instance to be destroyed.
 */
HEX_P void free_hex_instance(HexInstnace_t* handle);

/**
 * @brief Captures the next packet and parses it into a protocol chain.
 * @param handle Pointer to the active sniffer instance.
 * @return ProtocolNode_t* The head of the parsed linked list.
 * @warning Returns heap-allocated memory. Caller must use free_protocol_node() 
 * to prevent memory leaks.
 */
HEX_P ProtocolNode_t* read_next_packet(const HexInstnace_t* handle);

HEX_P void free_packet(ProtocolNode_t* node);

#endif
