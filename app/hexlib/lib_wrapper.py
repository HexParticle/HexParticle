# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

import ctypes
import typing
import os

from hexlib import ProtocolNode
from hexlib import ParsedPacket

class HexInstance(ctypes.Structure):
    _fields_ = [
        ("handle", ctypes.c_void_p)
    ]


class HexParticleLib:
    """Python wrapper for libhexp.so"""

    def __init__(self, lib_path: str = None):
        self.effective_lib_path = lib_path or "/usr/local/lib/HexParticle/libhexp.so"
        abs_path = os.path.abspath(self.effective_lib_path)

        if not os.path.exists(abs_path):
            raise FileNotFoundError(f"Could not find library at {abs_path}")
        
        try:
            lib = ctypes.CDLL(abs_path, mode=ctypes.RTLD_GLOBAL)
        except OSError as e:
            raise RuntimeError(f"Failed to load {abs_path}: {e}")
        
        print("[*] libhexp loaded")

        # Packet management
        lib.create_hex_instance.argtypes = [ctypes.c_char_p]
        lib.create_hex_instance.restype = HexInstance

        lib.read_next_packet.argtypes = [ctypes.POINTER(HexInstance)]
        lib.read_next_packet.restype = ctypes.POINTER(ProtocolNode)

        lib.apply_filter.argtypes = [ctypes.POINTER(ctypes.c_char)]
        lib.apply_filter.restype = ctypes.c_int

        lib.free_hex_instance.argtypes = [ctypes.POINTER(HexInstance)]
        lib.free_hex_instance.restype = None

        lib.free_packet.argtypes = [ctypes.POINTER(ProtocolNode)]
        lib.free_packet.restype = None

        # Interface management
        lib.get_all_interfaces_names.argtypes = [ctypes.POINTER(ctypes.c_int)]
        lib.get_all_interfaces_names.restype = ctypes.POINTER(ctypes.c_char_p)

        lib.free_interfaces_names.argtypes = [ctypes.POINTER(ctypes.c_char_p), ctypes.c_int]
        lib.free_interfaces_names.restype = None

        self.lib = lib


    def create_instance(self, iface_name: str) -> HexInstance:
        return self.lib.create_hex_instance(iface_name.encode("utf-8"))


    def read_next_packet(self, instance: HexInstance) -> typing.Optional[ParsedPacket]:
        node_ptr = self.lib.read_next_packet(instance)
        if not node_ptr:
            return None

        pwrapper = None
    
        try:
            pwrapper = ParsedPacket(node_ptr)
        finally:
            self.lib.free_packet(node_ptr)

        return pwrapper
    

    def apply_filter(self, new_filter: bytearray) -> typing.Optional[int]:
        if not new_filter: return None

        return self.lib.apply_filter(new_filter)


    def free_instance(self, instance: HexInstance):
        self.lib.free_hex_instance(instance)


    def get_all_interfaces(self) -> typing.List[str]:
        count = ctypes.c_int()
        names_ptr = self.lib.get_all_interfaces_names(ctypes.byref(count))
        names = [names_ptr[i].decode("utf-8") for i in range(count.value)]
        self.lib.free_interfaces_names(names_ptr, count)
        return names


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


    def next_packet(self) -> typing.Optional[ParsedPacket]:
        return self._lib.read_next_packet(self._instance)

    
    def apply_filter(self, new_filter: bytearray) -> int:
        return self._lib.apply_filter(new_filter)


    def close(self):
        if self._instance:
            self._lib.free_instance(self._instance)
            self._instance = None


    def __del__(self):
        self.close()