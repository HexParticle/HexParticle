/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#ifndef IP_PROTO_H
#define IP_PROTO_H

// IP protocol numbers list
#define IPPROTO_ICMP           0x01 /* Internet Control Message Protocol */
#define IPPROTO_IGMP           0x02 /* Internet Group Management Protocol */
#define IPPROTO_TCP            0x06 /* Transmission Control Protocol */
#define IPPROTO_UDP            0x11 /* User Datagram Protocol */
#define IPPROTO_V6_ROUTING     0x2B /* Routing header for IPV6 */
#define IPPROTO_TLSP           0x38 /* Transport Layer Security Protocol */
#define IPPROTO_EIGRP          0x58 /* Enhanced Interior Gateway Routing Protocol*/
#define IPPROTO_OSPF           0x59 /* Open Shortest Path First */

#define IPV4_ADDR_LEN		   0x04 /* IPv4 address's length: 4-bytes */
#define IPV6_ADDR_LEN		   0x10 /* IPv6 address's length: 16-bytes */

#endif
