# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

import ctypes

# --- IP Protocol Numbers (assigned by IANA) ---
# Used to identify the next level protocol in the IP header 'proto' field
IPPROTO_ICMP        = 0x01
IPPROTO_IGMP        = 0x02
IPPROTO_TCP         = 0x06
IPPROTO_UDP         = 0x11
IPPROTO_EIGRP       = 0x58
IPPROTO_OSPF        = 0x59

# Mapping for human-readable output during packet dissection
IP_PROTOCOL_NAMES = {
    IPPROTO_ICMP:        "ICMP(Internet Control Message Protocol)",
    IPPROTO_IGMP:        "IGMP(Internet Group Management Protocol)",
    IPPROTO_TCP:         "TCP(Transmission Control Protocol)",
    IPPROTO_UDP:         "UDP(User Datagram Protocol)",
    IPPROTO_EIGRP:       "EIGRP(Enhanced Interior Gateway Routing Protocol)",
    IPPROTO_OSPF:        "OSPF(Open Shorted Path First)",
}

'''
Internet Protocol Version 6's source and destination addresses' length
'''
IPV6_ADDR_LEN		= 16 # 16-bytes

'''
Represents a fixed-size array for IPv6 addresses (uint8_t[16])
'''
CT_IPV6_ADDRESS = ctypes.c_uint8 * IPV6_ADDR_LEN