# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

import typing
import ctypes
import ipaddress

def mac_to_str(bytes: bytearray) -> str:
	if len(bytes) != 6:
		raise ValueError("length must be 6")
	
	return ":".join(map(hex, bytes)).replace("0x", "")
    
def ip_to_str(octets: typing.List[int]) -> str:
	if len(octets) != 4:
		raise ValueError("length must be 4")

	return ".".join(map(str, octets))

def ipv6_to_str(octets) -> str:
	if len(octets) != 16:
		raise ValueError("length must be 16")

	return str(ipaddress.IPv6Address(bytes(octets)))


class ProtocolType:
    ETH			= 0
    IPV4 		= 1
    IPV6 		= 2
    ARP 		= 3
    TCP 		= 4
    UDP 		= 5
    ICMP 		= 6
    IPV6_EXT	= 7
    IPV6_EXT_HOP_BY_HOP = 8
    IPV6_EXT_DST_OPTS   = 9
    IPV6_EXT_FRAG       = 10
    ICMPV6              = 11
    RAW                 = 12


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
    ("length",  ctypes.c_uint32),               # Total length
    ("next", 	ctypes.POINTER(ProtocolNode))   # Link to the encapsulated protocol
]

__all__ = [
	'ProtocolNode',
	'ProtocolType',
	'COMMON_PORTS',
	'mac_to_str',
	'ip_to_str',
	'ipv6_to_str'
]