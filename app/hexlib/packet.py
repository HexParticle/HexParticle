# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

from hexlib.protocol import (
	ARPHeader,
    IPV4Header,
    IPV6Header,
    ICMPHeader,
    EtherHeader,
    TCPHeader,
    UDPHeader,
    TCPOption,
    ProtocolType
)

from hexlib.node import ProtocolNode

import ctypes

class ParsedPacket:
    TYPE_MAP = {
        ProtocolType.ETH:     	  EtherHeader,
        ProtocolType.IPV4:    	  IPV4Header,
        ProtocolType.ARP:     	  ARPHeader,
        ProtocolType.TCP:     	  TCPHeader,
        ProtocolType.UDP:     	  UDPHeader,
        ProtocolType.IPV6:		  IPV6Header,
        ProtocolType.ICMP:		  ICMPHeader,
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

        if isinstance(header, TCPHeader):
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
            if isinstance(layer, IPV4Header):
                self._network_layer_proto_type = ProtocolType.IPV4
            elif isinstance(layer, IPV6Header):
                self._network_layer_proto_type = ProtocolType.IPV6
            elif isinstance(layer, ARPHeader):
                self._network_layer_proto_type = ProtocolType.ARP
            elif isinstance(layer, TCPHeader):
                self._transport_layer_proto_type = ProtocolType.TCP
            elif isinstance(layer, UDPHeader):
                self._transport_layer_proto_type = ProtocolType.UDP
            elif isinstance(layer, ICMPHeader):
                self._transport_layer_proto_type = ProtocolType.ICMP

    
    def is_tcp_packet(self) -> bool:
        return self._transport_layer_proto_type == ProtocolType.TCP 


    def get_ip_layer(self):
        ip_layer = self._layers[1]
        if isinstance(ip_layer, IPV4Header) or isinstance(ip_layer, IPV6Header):
            return ip_layer
        else:
            raise ValueError("IP", "")
    

    def get_tcp_layer(self) -> TCPHeader:
        tcp_layer = self._layers[2]
        if isinstance(tcp_layer, TCPHeader):
            return tcp_layer
        else:
            raise ValueError("TCP", "")

    
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
    

    def insert_tcp_options(self, tcp_header: TCPHeader, opts_raw_stream, opts_length: int):
        options = []
        
        idx = 0
        while idx < opts_length:
            kind = opts_raw_stream[idx]

            if kind == 0: break # End of options list

            if kind == 1: # No operation
                idx += 1 # NOP takes 1 byte
                options.append(TCPOption.nop())
                continue

            if idx + 1 >= opts_length:
                break # might be a malformed packet

            length = opts_raw_stream[idx + 1]

            if length < 2 or (idx + length) > opts_length:
                break

            data_start = idx + 2
            data_end = idx + length
            data = opts_raw_stream[data_start:data_end]

            opt = TCPOption()
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