# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

import ctypes
import typing

from hexlib import ProtocolNode
from hexlib.packet import DissectedPacket

class HexInstance(ctypes.Structure):
    _fields_ = [
        ("handle", ctypes.c_void_p)
    ]


class HexParticleLib:
    """Python wrapper for libhexp.so"""

    def __init__(self, lib_path: str = "/usr/local/lib/HexParticle/libhexp.so"):
        self.lib = ctypes.CDLL(lib_path)
        if self.lib is None:
            raise RuntimeError(f"Failed to load {lib_path}")

        # Packet management
        self.lib.create_hex_instance.argtypes = [ctypes.c_char_p]
        self.lib.create_hex_instance.restype = HexInstance

        self.lib.read_next_packet.argtypes = [ctypes.POINTER(HexInstance)]
        self.lib.read_next_packet.restype = ctypes.POINTER(ProtocolNode)

        self.lib.free_hex_instance.argtypes = [ctypes.POINTER(HexInstance)]
        self.lib.free_hex_instance.restype = None

        self.lib.free_packet.argtypes = [ctypes.POINTER(ProtocolNode)]
        self.lib.free_packet.restype = None

        # Interface management
        self.lib.get_all_interfaces_names.argtypes = [ctypes.POINTER(ctypes.c_int)]
        self.lib.get_all_interfaces_names.restype = ctypes.POINTER(ctypes.c_char_p)

        self.lib.free_interfaces_names.argtypes = [ctypes.POINTER(ctypes.c_char_p), ctypes.c_int]
        self.lib.free_interfaces_names.restype = None


    def create_instance(self, iface_name: str) -> HexInstance:
        return self.lib.create_hex_instance(iface_name.encode("utf-8"))


    def read_next_packet(self, instance: HexInstance) -> typing.Optional[ProtocolNode]:
        ptr = self.lib.read_next_packet(ctypes.byref(instance))
        if not ptr:
            return None
        return ptr.contents


    def free_instance(self, instance: HexInstance):
        self.lib.free_hex_instance(ctypes.byref(instance))


    def get_all_interfaces(self) -> typing.List[str]:
        count = ctypes.c_int()
        names_ptr = self.lib.get_all_interfaces_names(ctypes.byref(count))
        names = [names_ptr[i].decode("utf-8") for i in range(count.value)]
        self.lib.free_interfaces_names(names_ptr, count)
        return names


    def free_packet(self, packet: ProtocolNode):
        self.lib.free_packet(ctypes.byref(packet))


class HexParticle():
    """
    A high-level packet sniffing interface for the HexParticle C library.
    """

    def __init__(self, device: str, lib_path: str = "/usr/local/lib/HexParticle/libhexp.so"):
        """
        Initializes the sniffer on the specified network interface.

        Args:
            device (str): Name of the network interface (e.g., 'eth0', 'wlan0').
        """
        self._lib = HexParticleLib(lib_path)
        self._instance = self._lib.create_instance(device)
        if not self._instance:
            raise RuntimeError(f"Failed to open device {device}")


    def next_packet(self) -> DissectedPacket:
        node_ptr = self._instance.read_next_packet(self._instance)
        if not node_ptr:
            return None

        pwrapper: DissectedPacket = None
    
        try:
            pwrapper = DissectedPacket(node_ptr)
        finally:
            self._lib.free_packet(node_ptr)

        return pwrapper


    def close(self):
        if self.handle:
            self._lib.free_instance(self._instance)
            self._instance = None


    def __del__(self):
        self.close()