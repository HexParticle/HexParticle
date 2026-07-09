# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

import ctypes
import typing
import os

from hexlib.node import ProtocolNode
from hexlib.packet import ParsedPacket

'''
PCAP live mode
'''
HEX_LIVE_MODE 		= 0x1

'''
PCAP offline mode
'''
HEX_OFFLINE_MODE 	= 0x2


'''
HexParticle library instance
'''
class HexInstance(ctypes.Structure):
    pass

'''
HexParticle library instance pointet type
'''
HexInstancePtr = ctypes.POINTER(HexInstance)

'''
Protocol node pointer type
'''
ProtocolNodePtr = ctypes.POINTER(ProtocolNode)

# ctypes type aliases
CStr = ctypes.POINTER(ctypes.c_char)
CInt = ctypes.c_int


class HexParticleLib:
    """Python wrapper for libhexp.so"""

    def __init__(
        self, 
        lib_path: str = None, 
    ):
        if lib_path is None:
            lib_path = "/usr/local/lib/HexParticle/libhexp.so"

        abs_path = os.path.abspath(lib_path)

        if not os.path.exists(abs_path):
            raise FileNotFoundError(f"Could not find library at {abs_path}")
        
        try:
            self.lib = ctypes.CDLL(abs_path, mode=ctypes.RTLD_GLOBAL)

            print("[*] libhexp loaded")
        except OSError as e:
            raise RuntimeError(f"Failed to load {abs_path}: {e}")

        # Packet management
        self.lib.create_hex_instance.argtypes = [CStr, CInt]
        self.lib.create_hex_instance.restype = HexInstancePtr

        self.lib.read_next_packet.argtypes = [HexInstancePtr]
        self.lib.read_next_packet.restype = ProtocolNodePtr

        self.lib.apply_filter.argtypes = [HexInstancePtr, CStr]
        self.lib.apply_filter.restype = ctypes.c_int

        self.lib.free_hex_instance.argtypes = [HexInstancePtr]
        self.lib.free_hex_instance.restype = None

        self.lib.free_packet.argtypes = [ProtocolNodePtr]
        self.lib.free_packet.restype = None

        # Interface management
        self.lib.get_all_interfaces_names.argtypes = [ctypes.POINTER(CInt)]
        self.lib.get_all_interfaces_names.restype = ctypes.POINTER(ctypes.c_char_p)

        self.lib.free_interfaces_names.argtypes = [ctypes.POINTER(ctypes.c_char_p), CInt]
        self.lib.free_interfaces_names.restype = None

        self._instance = None

    
    def initialize_hexp_instance(self, source: str, mode: int):
        if source is None or mode is None:
            print("Cannot initialize the library without the source and the mode.")
            return 

        self._instance = self.lib.create_hex_instance(source.encode("utf-8"), mode)

        if not self._instance:
            raise RuntimeError(f"Failed to open source '{source}' with mode '{mode}'.")


    def next_packet(self) -> typing.Optional[ParsedPacket]:
        if self._instance is None:
            print("next_packet called on null library instance")
            return None
        
        node_ptr = self.lib.read_next_packet(self._instance)
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


    def close(self):
        if self._instance is not None:
            self.lib.free_hex_instance(self._instance)
            self._instance = None


    def get_all_interfaces(self) -> typing.List[str]:
        count = ctypes.c_int()

        names_ptr = self.lib.get_all_interfaces_names(ctypes.byref(count))
        names = [names_ptr[i].decode("utf-8") for i in range(count.value)]
        
        self.lib.free_interfaces_names(names_ptr, count)
        
        return names
    

    def __del__(self):
        self.close()