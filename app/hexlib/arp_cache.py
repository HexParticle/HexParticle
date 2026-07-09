import ctypes
import typing

class ArpAlert(ctypes.Structure):
    _fields_ = [
        ("ip_address", ctypes.c_uint32),
        ("cached_mac", ctypes.c_uint8 * 6),
        ("poison_mac", ctypes.c_uint8 * 6)
    ]


ARP_ALERT_CALLBACK_TYPE = ctypes.CFUNCTYPE(None, ctypes.POINTER(ArpAlert))