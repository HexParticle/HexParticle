# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

import ctypes
import typing
from dataclasses import dataclass

from . import protocols
# import protocols


class HexInstance(ctypes.Structure):
    _fields_ = [
        ("handle", ctypes.c_void_p)
    ]


lib_hexp = ctypes.CDLL("/usr/local/lib/HexParticle/libhexp.so")
if lib_hexp is None:
    raise RuntimeError("libhexp not found")

'''
These functions are for capturing and managing packets
'''
lib_hexp.create_hex_instance.argtypes = [ctypes.c_char_p]
lib_hexp.create_hex_instance.restype = HexInstance

lib_hexp.read_next_packet.argtypes = [ctypes.POINTER(HexInstance)]
lib_hexp.read_next_packet.restype = ctypes.POINTER(protocols.ProtocolNode)

lib_hexp.free_hex_instance.argtypes = [ctypes.POINTER(HexInstance)]
lib_hexp.free_hex_instance.restype = None

'''
Interface related functions
'''
lib_hexp.get_all_interfaces_names.argtypes = [ctypes.POINTER(ctypes.c_int)]
lib_hexp.get_all_interfaces_names.restype = ctypes.POINTER(ctypes.c_char_p)

lib_hexp.free_interfaces_names.argtypes = [ctypes.POINTER(ctypes.c_char_p), ctypes.c_int]
lib_hexp.free_interfaces_names.restype = None

# free the packet
lib_hexp.free_packet.argtypes = [ctypes.POINTER(protocols.ProtocolNode)]
lib_hexp.free_packet.restype = None


class InterfaceManager:
    def get_all_interface_names(self):
        self.count = ctypes.c_int()
        self.interfaces = lib_hexp.get_all_interfaces_names(ctypes.byref(self.count))
        if not self.interfaces:
            raise RuntimeError(f"Failed to get interface names")
        return [self.interfaces[i].decode("UTF-8") for i in range(self.count.value)]


    def __del__(self):
        lib_hexp.free_interfaces_names(self.interfaces, self.count)


class PacketWrapper:
    TYPE_MAP = {
        protocols.ProtocolType.ETH:     	  protocols.EtherHeader,
        protocols.ProtocolType.IPV4:    	  protocols.IPV4Header,
        protocols.ProtocolType.ARP:     	  protocols.ARPHeader,
        protocols.ProtocolType.TCP:     	  protocols.TCPHeader,
        protocols.ProtocolType.UDP:     	  protocols.UDPHeader,
        protocols.ProtocolType.IPV6:		  protocols.IPV6Header,
        protocols.ProtocolType.ICMP:		  protocols.ICMPHeader,
    }
    
    def __init__(self, head_node_ptr):
        self.layers = []
        self.raw = bytearray()
        self.length = None
        
        current = head_node_ptr
        
        while current:
            node = current.contents
            if node.type == protocols.ProtocolType.IPV6_EXT:
                print("ipv6 ext header")

            header_obj = self._cast_header(node)
            
            if header_obj is not None:
                self.layers.append(header_obj)
                self.raw.extend(bytes(header_obj))

            current = node.next


    def _cast_header(self, node):
        header_class = PacketWrapper.TYPE_MAP.get(node.type)
    
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

        if isinstance(header, protocols.TCPHeader):
            if header.header_length > 20:
                opts_length = header.header_length - 20
                raw_data_ptr = ctypes.cast(node.hdr, ctypes.POINTER(ctypes.c_uint8 * header.header_length))
                opts_bytes = raw_data_ptr.contents[20:header.header_length]
                self.insert_tcp_options(header, opts_bytes, opts_length)
            else:
                header.options = []

        return header
    

    def insert_tcp_options(self, tcp_header: protocols.TCPHeader, opts_raw_stream, opts_length: int):
        options = []
        
        idx = 0
        while idx < opts_length:
            kind = opts_raw_stream[idx]

            if kind == 0: break # End of options list

            if kind == 1: # No operation
                idx += 1 # NOP takes 1 byte
                options.append(protocols.TCPOption.nop())
                continue

            if idx + 1 >= opts_length:
                break # might be a malformed packet

            length = opts_raw_stream[idx + 1]

            if length < 2 or (idx + length) > opts_length:
                break

            data_start = idx + 2
            data_end = idx + length
            data = opts_raw_stream[data_start:data_end]

            opt = protocols.TCPOption()
            opt.kind = kind
            opt.length = length
            opt.set_data(data)
            options.append(opt)

            idx += length

        tcp_header.set_options(options)


    def __repr__(self):
        return " -> ".join([type(l).__name__ for l in self.layers])


class HexParticle():
    """
    A high-level packet sniffing interface for the HexParticle C library.
    """

    def __init__(self, device: str):
        """
        Initializes the sniffer on the specified network interface.

        Args:
            device (str): Name of the network interface (e.g., 'eth0', 'wlan0').
        """
        self.handle: HexInstance = lib_hexp.create_hex_instance(device.encode('utf-8'))
        if not self.handle:
            raise RuntimeError(f"Failed to open device {device}")


    def next_packet(self) -> PacketWrapper:
        node_ptr = lib_hexp.read_next_packet(self.handle)
        if not node_ptr:
            return None

        pwrapper = None
    
        try:
            pwrapper = PacketWrapper(node_ptr)
        finally:
            lib_hexp.free_packet(node_ptr)

        return pwrapper


    def close(self):
        if self.handle:
            lib_hexp.free_hex_instance(self.handle)
            self.handle = None


    def __del__(self):
        self.close()


if __name__ == "__main__":
    hex = HexParticle("en0")
    while True:
        packet = hex.next_packet()
