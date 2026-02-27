# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

import ctypes

from . import ip

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


# --- ARP Operation Types ---
ARP_REQUEST 	= 1
ARP_RESPONSE	= 2


# Represents a fixed-size array for IPv4 addresses (uint8_t[4])
CT_IPV4_ADDRESS = ctypes.c_uint8 * 4
# Represents a fixed-size array for MAC addresses (uint8_t[6])
CT_MAC_ADDRESS  = ctypes.c_uint8 * 6

def get_protocol_name(proto_number: int) -> str:
    return ip.IP_PROTOCOL_NAMES.get(proto_number, "Unknown Protocol")

class ProtocolType:
    ETH		= 0
    IPV4 	= 1
    IPV6 	= 2
    ARP 	= 3
    TCP 	= 4
    UDP 	= 5,
    ICMP 	= 6


# Protocol specific constants
COMMON_PORTS = {
    20: "FTP", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP", 443: "HTTPS", 3389: "RDP"
}


# --- Hierarchical Node Structure ---
class ProtocolNode(ctypes.Structure):
    """
    Python representation of the C linked-list node.
    Each node points to a specific protocol header and the next layer.
    """
    pass

ProtocolNode._fields_ = [
    ("type", 	ctypes.c_int),                  # Internal ProtocolType
    ("hdr", 	ctypes.c_void_p),               # Pointer to the actual header struct
    ("hdr_len", ctypes.c_uint32),               # Size of the header (for variable length parsing)
    ("next", 	ctypes.POINTER(ProtocolNode))   # Link to the encapsulated protocol
]

# --- Protocol Header Definitions ---

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
        ('len', 		ctypes.c_uint32),
        ('vlan_count',	ctypes.c_int),
        ('vlans',		VlanTag * MAX_VLAN_STACK)
    ]

class IPV4Header(ctypes.Structure):
    """Maps to IPV4Header_t. Represents the standard 20-byte IPv4 header."""
    _pack_ = 1
    _fields_ = [
        ('ver_ihl', 	ctypes.c_uint8),        # Version (4 bits) + IHL (4 bits)
        ('dscp_ecn', 	ctypes.c_uint8),        # DiffServ + ECN
        ('len', 		ctypes.c_uint16),       # Total Packet Length
        ('id', 			ctypes.c_uint16),       # Identification
        ('flags_off', 	ctypes.c_uint16),       # Flags + Fragment Offset
        ('ttl', 		ctypes.c_uint8),        # Time to Live
        ('proto', 		ctypes.c_uint8),        # Protocol
        ('chk', 		ctypes.c_uint16),       # Header Checksum
        ('src', 		CT_IPV4_ADDRESS),       # Source IP
        ('dst', 		CT_IPV4_ADDRESS)        # Destination IP
    ]


class IPV6Header(ctypes.Structure):
    """Maps to IPV6Header_t. Represents the standard 40-byte IPv6 header."""
    _pack_ = 1
    _fields_ = [
        ('ver_tc_fl', 		ctypes.c_uint32),
        ('len', 			ctypes.c_uint16),
        ('next_hdr',		ctypes.c_uint8),
        ('hop_limit', 		ctypes.c_uint8),
        ('src', 			ip.CT_IPV6_ADDRESS),
        ('dst', 			ip.CT_IPV6_ADDRESS)
    ]


class ARPHeader(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('htype', 	ctypes.c_uint16),
        ('ptype', 	ctypes.c_uint16),
        ('hlen', 	ctypes.c_uint8),
        ('plen', 	ctypes.c_uint8),
        ('op', 		ctypes.c_uint16),
        ('sha', 	CT_MAC_ADDRESS),
        ('spa', 	CT_IPV4_ADDRESS),
        ('tha', 	CT_MAC_ADDRESS),
        ('tpa', 	CT_IPV4_ADDRESS)
    ]


class TCPHeader(ctypes.Structure):
    """Maps to TCPHeader_t. Represents the standard TCP segment header."""
    _pack_ = 1
    _fields_ = [
        ("sport", 	ctypes.c_uint16),    # Source Port
        ("dport", 	ctypes.c_uint16),    # Destination Port
        ("seq", 	ctypes.c_uint32),      # Sequence Number
        ("ack", 	ctypes.c_uint32),      # Acknowledgment Number
        ("off_res", ctypes.c_uint8),   # Data Offset + Reserved bits
        ("flags", 	ctypes.c_uint8),     # Control Flags (SYN, ACK, FIN, etc.)
        ("win", 	ctypes.c_uint16),      # Window Size
        ("chk", 	ctypes.c_uint16),      # Checksum
        ("urg", 	ctypes.c_uint16),      # Urgent Pointer
    ]


class UDPHeader(ctypes.Structure):
    """Maps to UDPHeader_t. Represents the standard UDP segment header."""
    _pack_ = 1
    _fields_ = [
        ('sport', 	ctypes.c_uint16),
        ('dport', 	ctypes.c_uint16),
        ('length', 	ctypes.c_uint16),
        ('cksum', 	ctypes.c_uint16)
    ]


# ICMP-related classes
class ICMPEcho(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("id", ctypes.c_uint16),
        ("seq", ctypes.c_uint16),
    ]


class ICMPFrag(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("unused", ctypes.c_uint16),
        ("mtu", ctypes.c_uint16),
    ]


class ICMPRest(ctypes.Union):
    _pack_ = 1
    _fields_ = [
        ("echo", ICMPEcho),
        ("gateway", ctypes.c_uint32),
        ("frag", ICMPFrag),
        ("raw", ctypes.c_uint32),
    ]


class ICMPHeader(ctypes.Structure):
    """Maps to ICMPHeader_t. Represents the standard ICMP segment header."""
    _pack_ = 1
    _fields_ = [
        ("type", 		ctypes.c_uint8),
        ("code", 		ctypes.c_uint8),
        ("cksum", 		ctypes.c_uint16),
        ("rest",		ICMPRest)
    ]