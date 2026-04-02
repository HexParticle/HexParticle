# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

import ctypes

from hexlib import ProtocolNode
from hexlib.packet import DissectedPacket

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
lib_hexp.read_next_packet.restype = ctypes.POINTER(ProtocolNode)

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
lib_hexp.free_packet.argtypes = [ctypes.POINTER(ProtocolNode)]
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


    def next_packet(self) -> DissectedPacket:
        node_ptr = lib_hexp.read_next_packet(self.handle)
        if not node_ptr:
            return None

        pwrapper = None
    
        try:
            pwrapper = DissectedPacket(node_ptr)
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