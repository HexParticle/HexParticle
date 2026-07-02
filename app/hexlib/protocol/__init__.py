# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

from .icmp import ICMPHeader
from . import icmp

from .tcp import TCPHeader, TCPOption
from . import tcp

from .ip import IPV4Header, IPV6Header, AnyIPHeader
from . import ip

from .ether import EtherHeader, VlanTag
from . import ether

from .udp import UDPHeader
from . import udp

from .arp import ARPHeader
from . import arp

class ProtocolType:
    ETH					= 0
    IPV4 				= 1
    IPV6 				= 2
    ARP 				= 3
    TCP 				= 4
    UDP 				= 5
    ICMP 				= 6
    IPV6_EXT			= 7
    IPV6_EXT_HOP_BY_HOP = 8
    IPV6_EXT_DST_OPTS   = 9
    IPV6_EXT_FRAG       = 10
    ICMPV6              = 11
    RAW                 = 12

__all__ =  [
	'ICMPHeader',
	'icmp',
	'TCPHeader',
	'TCPOption',
	'tcp',
	'IPV4Header',
	'IPV6Header',
	'AnyIPHeader',
	'ip',
	'UDPHeader',
	'udp',
	'EtherHeader',
	'VlanTag',
	'ether',
	'ARPHeader',
	'arp',
    'ProtocolType'
]