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
    0:   "IPv6 Hop-by-Hop Options",
    1:   "Internet Control Message Protocol",
    2:   "Internet Group Management Protocol",
    4:   "IP in IP Encapsulation",
    6:   "Transmission Control Protocol",
    17:  "User Datagram Protocol",
    41:  "IPv6 Encapsulation",
    43:  "IPv6 Routing Header",
    44:  "IPv6 Fragment Header",
    47:  "Generic Routing Encapsulation",
    50:  "Encapsulating Security Payload",
    51:  "Authentication Header",
    58:  "ICMP for IPv6",
    59:  "No Next Header",
    60:  "IPv6 Destination Options",
    88:  "Enhanced Interior Gateway Routing Protocol",
    89:  "Open Shortest Path First",
    132: "Stream Control Transmission Protocol",
    135: "Mobility Header",
}

IP_PROTOCOL_NAMES_SHORT = {
    0: "HOPOPT",     # IPv6 Hop-by-Hop Option
    1: "ICMP",       # Internet Control Message Protocol (v4)
    2: "IGMP",       # Internet Group Management Protocol
    6: "TCP",        # Transmission Control Protocol
    17: "UDP",       # User Datagram Protocol
    41: "IPv6",      # IPv6 encapsulation (6to4)
    43: "IPv6-Route",# Routing Header for IPv6
    44: "IPv6-Frag", # Fragment Header for IPv6
    47: "GRE",       # General Routing Encapsulation
    50: "ESP",       # Encap Security Payload
    51: "AH",        # Authentication Header
    58: "ICMPv6",    # ICMP for IPv6
    59: "IPv6-NoNxt",# No Next Header for IPv6
    60: "IPv6-Opts", # Destination Options for IPv6
    89: "OSPF",      # OSPF Routing Protocol
    132: "SCTP",     # Stream Control Transmission Protocol
}

'''
Internet Protocol Version 6's source and destination addresses' length
'''
IPV6_ADDR_LEN		= 16 # 16-bytes

'''
Represents a fixed-size array for IPv6 addresses (uint8_t[16])
'''
CT_IPV6_ADDRESS = ctypes.c_uint8 * IPV6_ADDR_LEN


IPV6_EXT_HOP_BY_HOP		= 0
IPV6_EXT_ROUTING		= 43
IPV6_EXT_FRAGMENT		= 44
IPV6_EXT_AUTH_HDR		= 51 # Authentication Header
IPV6_EXT_ESP			= 50 # Encapsulating Security Payload
IPV6_EXT_DEST_OPTS		= 60 # Destination Options
IPV6_EXT_MOBILITY		= 135
