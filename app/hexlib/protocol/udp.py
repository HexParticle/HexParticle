# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

import ctypes

class UDPHeader(ctypes.Structure):
    """Maps to UDPHeader_t. Represents the standard UDP segment header."""
    _pack_ = 1
    _fields_ = [
        ('sport', 	ctypes.c_uint16),
        ('dport', 	ctypes.c_uint16),
        ('length', 	ctypes.c_uint16),
        ('cksum', 	ctypes.c_uint16)
    ]