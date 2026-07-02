# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

import typing
import ipaddress

from hexlib.lib_wrapper import (
    HexParticleLib,
    HEX_LIVE_MODE,
    HEX_OFFLINE_MODE,
    HexInstance
)

from hexlib.protocol import (
	AnyIPHeader,
	ARPHeader,
    IPV4Header,
    IPV6Header,
    ICMPHeader,
    EtherHeader,
    TCPHeader,
    UDPHeader,
    TCPOption,
    VlanTag
)

from hexlib.node import ProtocolNode
from hexlib.packet import ParsedPacket


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


# Protocol specific constants
COMMON_PORTS = {
    20: "FTP", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP", 443: "HTTPS", 3389: "RDP"
}
    

class PacketError(Exception):
    """Base class for packet-related errors."""


class UnexpectedLayerTypeError(PacketError, ValueError):
    def __init__(self, expected = 'Unknown', actual = 'Unknown'):
        super().__init__(f"Expected '{expected}', got '{actual}'")
        self.expected = expected
        self.actual = actual


__all__ = [
    'ProtocolNode',
    'ProtocolType',
    'COMMON_PORTS',
    'mac_to_str',
    'ip_to_str',
    'ipv6_to_str',
    'ParsedPacket',
    'PacketError',
    'UnexpectedLayerTypeError',
    'HexParticleLib',
    'HEX_LIVE_MODE',
    'HEX_OFFLINE_MODE',
    'HexInstance',
	'AnyIPHeader',
	'ARPHeader',
    'IPV4Header',
    'IPV6Header',
    'ICMPHeader',
    'EtherHeader',
    'TCPHeader',
    'UDPHeader',
    'TCPOption',
    'VlanTag'
]