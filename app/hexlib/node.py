# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

import ctypes

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