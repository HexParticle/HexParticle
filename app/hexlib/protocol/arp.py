# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

import ctypes

from hexlib.protocol.ip import CT_IPV4_ADDRESS
from hexlib.protocol.ether import CT_MAC_ADDRESS


# --- ARP Operation Types ---
ARP_REQUEST 	= 1
ARP_RESPONSE	= 2


class ARPHeader(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('htype', 	ctypes.c_uint16),
        ('ptype', 	ctypes.c_uint16),
        ('hlen', 	ctypes.c_uint8),
        ('plen', 	ctypes.c_uint8),
        ('op', 		ctypes.c_uint16),
        ('sha', 	CT_MAC_ADDRESS),
        ('spa', 	CT_IPV4_ADDRESS),
        ('tha', 	CT_MAC_ADDRESS),
        ('tpa', 	CT_IPV4_ADDRESS)
    ]