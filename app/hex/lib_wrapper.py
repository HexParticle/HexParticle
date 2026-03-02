# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

import ctypes
import typing

from . import protocols
# import protocols


class HexInstance(ctypes.Structure):
    _fields_ = [
        ("handle", ctypes.c_void_p)
    ]


lib_hexp = ctypes.CDLL("/usr/local/lib/HexParticle/libhexp.so")

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
        protocols.ProtocolType.ETH:     	protocols.EtherHeader,
        protocols.ProtocolType.IPV4:    	protocols.IPV4Header,
        protocols.ProtocolType.ARP:     	protocols.ARPHeader,
        protocols.ProtocolType.TCP:     	protocols.TCPHeader,
        protocols.ProtocolType.UDP:     	protocols.UDPHeader,
        protocols.ProtocolType.IPV6:		protocols.IPV6Header,
        protocols.ProtocolType.ICMP:		protocols.ICMPHeader,
        protocols.ProtocolType.IPV6_EXT: 	protocols.IPV6ExtHeader
    }
    
    def __init__(self, head_node_ptr):
        self.layers = []
        self.raw = bytearray()
        
        current = head_node_ptr
        
        while current:
            node = current.contents
            if node.type == protocols.ProtocolType.IPV6_EXT:
                print("ext header")

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

        ptr = ctypes.cast(node.hdr, ctypes.POINTER(header_class))
        return header_class.from_buffer_copy(ptr.contents)


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
        
        self._callbacks: typing.Dict[int, typing.List[typing.Callable[[dict], None]]] = {}


    def next_packet(self) -> PacketWrapper:
        node_ptr = lib_hexp.read_next_packet(self.handle)
        if not node_ptr:
            return None
    
        try:
            # Build the wrapper while the C memory is guaranteed to be locked
            pwrapper = PacketWrapper(node_ptr)
            return pwrapper
        finally:
            # Use the pointer directly to ensure we are freeing exactly what we got
            lib_hexp.free_packet(node_ptr)


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