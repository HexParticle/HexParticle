# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

import ctypes 
import typing

FLAG_MEANING = {
	1: 		"FIN",
	2: 		"SYN",
	4: 		"RST",
	8: 		"PSH",
	16: 	"ACK",
	32: 	"URG",
	64: 	"ECE",
	128: 	"CWR"
}

TCP_OPTION_NOP = 				0x1
TCP_OPTION_MSS = 				0x2
TCP_OPTION_WINDOW_SCALE = 		0x3
TCP_OPTION_SACK_PERMITTED = 	0x4
TCP_OPTION_SACK = 				0x5
TCP_OPTION_TIMESTAMPS = 		0x8
TCP_OPTION_UTO = 				0x1C
TCP_OPTION_AUTH = 				0x1D
TCP_OPTION_MPTCP = 				0x1E

class TCPOption(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("kind", 	ctypes.c_uint8),
        ("length", 	ctypes.c_uint8)
    ]

    def set_data(self, data):
        self.data = data

    @staticmethod
    def nop():
        opt = TCPOption()
        opt.kind = 1
        opt.length = 1
        opt.set_data(None)
        return opt
    

class TCPHeader(ctypes.Structure):
    """Maps to TCPHeader_t. Represents the standard TCP segment header."""
    _pack_ = 1
    _fields_ = [
        ("sport", 	ctypes.c_uint16),    # Source Port
        ("dport", 	ctypes.c_uint16),    # Destination Port
        ("seq", 	ctypes.c_uint32),      # Sequence Number
        ("ack", 	ctypes.c_uint32),      # Acknowledgment Number
        ("off_res", ctypes.c_uint8),   # Data Offset + Reserved bits
        ("flags", 	ctypes.c_uint8),     # Control Flags (SYN, ACK, FIN, etc.)
        ("win", 	ctypes.c_uint16),      # Window Size
        ("chk", 	ctypes.c_uint16),      # Checksum
        ("urg", 	ctypes.c_uint16),      # Urgent Pointer
    ]

    @property
    def header_length(self):
        # The 'off_res' high 4 bits * 4 gives the total header size in bytes
        return (self.off_res >> 4) * 4

    def set_options(self, options: typing.List[TCPOption]):
        self.options = options

    def nop(self):
        for option in self.options:
            if option.kind == TCP_OPTION_NOP:
                return True
        return False

    def mss(self):
        for option in self.options:
            if option.kind == TCP_OPTION_MSS:
                return option.data
        return None

    def window_scale(self):
        for option in self.options:
            if int(option.kind) == TCP_OPTION_WINDOW_SCALE:
                return option.data
        return None

    def sack_premitted(self):
        for option in self.options:
            if int(option.kind) == TCP_OPTION_SACK_PERMITTED:
                return option.data
        return None

    def sack(self):
        for option in self.options:
            if option.kind == TCP_OPTION_SACK:
                return option.data
        return None

    def timestamps(self):
        for option in self.options:
            if option.kind == TCP_OPTION_TIMESTAMPS:
                timestamp = 0
                for idx in range(option.length - 3, 0, -1):
                    timestamp |= option.data[idx] << (idx * 8)
                return timestamp
        return None

    def flags_num(self) -> int:
        return self.flags
    
    def flags_str(self):
        return [
            FLAG_MEANING.get(f)
            for f in [1, 2, 4, 8, 16, 32, 64, 128]
            if (f & self.flags)
        ]