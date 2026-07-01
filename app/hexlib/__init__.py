# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

import typing
import ctypes
import ipaddress
import hexlib.protocol as proto

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


class ParsedPacket:
    TYPE_MAP = {
        ProtocolType.ETH:     	  proto.EtherHeader,
        ProtocolType.IPV4:    	  proto.IPV4Header,
        ProtocolType.ARP:     	  proto.ARPHeader,
        ProtocolType.TCP:     	  proto.TCPHeader,
        ProtocolType.UDP:     	  proto.UDPHeader,
        ProtocolType.IPV6:		  proto.IPV6Header,
        ProtocolType.ICMP:		  proto.ICMPHeader,
    }
    
    def __init__(self, head_node_ptr: ProtocolNode):
        self._layers = []
        self._raw = bytearray()
        self.length = None

        self._transport_layer_proto_type: ProtocolType = None
        self._network_layer_proto_type: ProtocolType = None
        self._data_link_layer_proto_type: ProtocolType = ProtocolType.ETH
        
        current = head_node_ptr
        
        while current:
            node = current.contents
            if node.type == ProtocolType.IPV6_EXT:
                print("ipv6 ext header")

            header_obj = self._cast_header(node)
            
            if header_obj is not None:
                self._layers.append(header_obj)
                self._raw.extend(bytes(header_obj))

            current = node.next
        
        self.identify_layer_types()


    def _cast_header(self, node):
        header_class = ParsedPacket.TYPE_MAP.get(node.type)
    
        if not header_class:
            print(f"Unknown protocol type: {node.type}")
            return None
        
        if not node.hdr:
            print(f"SKIPPED: Node type {node.type} has a NULL header pointer!")
            return None

        if getattr(node, "length", None) is None:
            print("Field 'length' literally does not exist on node!")
            return None
        elif self.length is None:
            self.length = node.length

        ptr = ctypes.cast(node.hdr, ctypes.POINTER(header_class))
        header = header_class.from_buffer_copy(ptr.contents)

        if isinstance(header, proto.TCPHeader):
            if header.header_length > 20:
                opts_length = header.header_length - 20
                raw_data_ptr = ctypes.cast(node.hdr, ctypes.POINTER(ctypes.c_uint8 * header.header_length))
                opts_bytes = raw_data_ptr.contents[20:header.header_length]
                self.insert_tcp_options(header, opts_bytes, opts_length)
            else:
                header.options = []

        return header

    
    def identify_layer_types(self):
        for layer in self._layers:
            if isinstance(layer, proto.IPV4Header):
                self._network_layer_proto_type = ProtocolType.IPV4
            elif isinstance(layer, proto.IPV6Header):
                self._network_layer_proto_type = ProtocolType.IPV6
            elif isinstance(layer, proto.ARPHeader):
                self._network_layer_proto_type = ProtocolType.ARP
            elif isinstance(layer, proto.TCPHeader):
                self._transport_layer_proto_type = ProtocolType.TCP
            elif isinstance(layer, proto.UDPHeader):
                self._transport_layer_proto_type = ProtocolType.UDP
            elif isinstance(layer, proto.ICMPHeader):
                self._transport_layer_proto_type = ProtocolType.ICMP

    
    def is_tcp_packet(self) -> bool:
        return self._transport_layer_proto_type == ProtocolType.TCP 


    def get_ip_layer(self):
        ip_layer = self._layers[1]
        if isinstance(ip_layer, proto.IPV4Header) or isinstance(ip_layer, proto.IPV6Header):
            return ip_layer
        else:
            raise UnexpectedLayerTypeError("IP", "")
    

    def get_tcp_layer(self) -> proto.TCPHeader:
        tcp_layer = self._layers[2]
        if isinstance(tcp_layer, proto.TCPHeader):
            return tcp_layer
        else:
            raise UnexpectedLayerTypeError("TCP", "")

    
    def is_ip_packet(self):
        return self.is_ipv4_packet() or self.is_ipv6_packet()

    
    def is_ipv4_packet(self) -> bool:
        return self._network_layer_proto_type == ProtocolType.IPV4

    
    def is_udp_packet(self) -> bool:
        return self._transport_layer_proto_type == ProtocolType.UDP 

    
    def is_ipv6_packet(self) -> bool:
        return self._network_layer_proto_type == ProtocolType.IPV6


    def is_icmp_packet(self) -> bool:
        return self._transport_layer_proto_type == ProtocolType.ICMP
    
    
    def is_arp_packet(self) -> bool:
        return self._network_layer_proto_type == ProtocolType.ARP

    
    def packets_count(self) -> int:
        return len(self._layers)
    

    def insert_tcp_options(self, tcp_header: proto.TCPHeader, opts_raw_stream, opts_length: int):
        options = []
        
        idx = 0
        while idx < opts_length:
            kind = opts_raw_stream[idx]

            if kind == 0: break # End of options list

            if kind == 1: # No operation
                idx += 1 # NOP takes 1 byte
                options.append(proto.TCPOption.nop())
                continue

            if idx + 1 >= opts_length:
                break # might be a malformed packet

            length = opts_raw_stream[idx + 1]

            if length < 2 or (idx + length) > opts_length:
                break

            data_start = idx + 2
            data_end = idx + length
            data = opts_raw_stream[data_start:data_end]

            opt = proto.TCPOption()
            opt.kind = kind
            opt.length = length
            opt.set_data(data)
            options.append(opt)

            idx += length

        tcp_header.set_options(options)


    def __repr__(self):
        return " -> ".join([type(l).__name__ for l in self._layers])

    
    def __iter__(self):
        return iter(self._layers)

    
    def __len__(self):
        return len(self._layers)   
    

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
    'UnexpectedLayerTypeError'
]