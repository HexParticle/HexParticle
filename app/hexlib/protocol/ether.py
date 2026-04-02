# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

import ctypes

# Represents a fixed-size array for MAC addresses (uint8_t[6])
CT_MAC_ADDRESS  = ctypes.c_uint8 * 6

# --- Layer 2 EtherTypes ---
# Used in the Ethernet frame to determine which protocol is encapsulated
ETHER_TYPE_IPV4 = 0x0800 
ETHER_TYPE_IPV6 = 0x86DD 
ETHER_TYPE_ARP 	= 0x0806 

ETHER_TYPE_NAMES = {
    ETHER_TYPE_ARP:		"Address Resolution Protocol",
    ETHER_TYPE_IPV4:	"Internet Protocol Version 4",
    ETHER_TYPE_IPV6:	"Internet Protocol Version 6",
}

MAX_VLAN_STACK = 4

class VlanTag(ctypes.Structure):
    """Maps to VlanTag_t"""
    _pack_ = 1
    _fields_ = [
        ('tpid', 	ctypes.c_uint16),
        ('tci',  	ctypes.c_uint16)
    ]


class EtherHeader(ctypes.Structure):
    """Maps to EtherHeader_t"""
    _pack_ = 1
    _fields_ = [
        ('src_mac', 	CT_MAC_ADDRESS), 
        ('dst_mac', 	CT_MAC_ADDRESS),
        ('type', 		ctypes.c_uint16),
        ('vlan_count',	ctypes.c_uint8),
        ('vlans',		VlanTag * MAX_VLAN_STACK)
    ]