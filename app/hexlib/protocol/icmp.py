# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

import ctypes

class ICMP:
    class Type:
        ECHOREPLY 	= 0
        UNREACH 	= 3
        ECHOREQUEST = 8

    class Code:
        UNREACH_NET 				= 0
        UNREACH_HOST 				= 1
        UNREACH_PROTOCOL 			= 2
        UNREACH_PORT 				= 3
        UNREACH_NEEDFRAG 			= 4
        UNREACH_SRCFAIL 			= 5
        UNREACH_NET_UNKNOWN 		= 6
        UNREACH_HOST_UNKNOWN 		= 7
        UNREACH_ISOLATED 			= 8
        UNREACH_NET_PROHIB 			= 9
        UNREACH_HOST_PROHIB 		= 10
        UNREACH_TOSNET 				= 11
        UNREACH_TOSHOST 			= 12
        UNREACH_FILTER_PROHIB 		= 13
        UNREACH_HOST_PRECEDENCE 	= 14
        UNREACH_PRECEDENCE_CUTOFF 	= 15


ICMP_TYPE_MEANING = {
    ICMP.Type.ECHOREPLY:        "Echo reply",
    ICMP.Type.UNREACH:          "Destination unreachable",
    ICMP.Type.ECHOREQUEST:      "Echo request"
}

def icmp_type_meaning(type_):
    return ICMP_TYPE_MEANING.get(type_, None)


ICMP_MEANING = {
    # Destination Unreachable
    (ICMP.Type.UNREACH, ICMP.Code.UNREACH_NET):                 "Destination network unreachable",
    (ICMP.Type.UNREACH, ICMP.Code.UNREACH_HOST):                "Destination host unreachable",
    (ICMP.Type.UNREACH, ICMP.Code.UNREACH_PROTOCOL):            "Protocol unreachable",
    (ICMP.Type.UNREACH, ICMP.Code.UNREACH_PORT):                "Port unreachable",
    (ICMP.Type.UNREACH, ICMP.Code.UNREACH_NEEDFRAG):            "Fragmentation needed (DF set)",
    (ICMP.Type.UNREACH, ICMP.Code.UNREACH_SRCFAIL):             "Source route failed",
    (ICMP.Type.UNREACH, ICMP.Code.UNREACH_NET_UNKNOWN):         "Network unknown",
    (ICMP.Type.UNREACH, ICMP.Code.UNREACH_HOST_UNKNOWN):        "Host unknown",
    (ICMP.Type.UNREACH, ICMP.Code.UNREACH_ISOLATED):            "Source host isolated",
    (ICMP.Type.UNREACH, ICMP.Code.UNREACH_NET_PROHIB):          "Network administratively prohibited",
    (ICMP.Type.UNREACH, ICMP.Code.UNREACH_HOST_PROHIB):         "Host administratively prohibited",
    (ICMP.Type.UNREACH, ICMP.Code.UNREACH_TOSNET):              "Network unreachable for TOS",
    (ICMP.Type.UNREACH, ICMP.Code.UNREACH_TOSHOST):             "Host unreachable for TOS",
    (ICMP.Type.UNREACH, ICMP.Code.UNREACH_FILTER_PROHIB):       "Communication administratively prohibited",
    (ICMP.Type.UNREACH, ICMP.Code.UNREACH_HOST_PRECEDENCE):     "Host precedence violation",
    (ICMP.Type.UNREACH, ICMP.Code.UNREACH_PRECEDENCE_CUTOFF):   "Precedence cutoff in effect",
}

def icmp_meaning(type_, code):
    return ICMP_MEANING.get((type_, code), None)


# ICMP-related classes
class ICMPEcho(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("id", ctypes.c_uint16),
        ("seq", ctypes.c_uint16),
    ]


class ICMPFrag(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("unused", ctypes.c_uint16),
        ("mtu", ctypes.c_uint16),
    ]


class ICMPRest(ctypes.Union):
    _pack_ = 1
    _fields_ = [
        ("echo", ICMPEcho),
        ("gateway", ctypes.c_uint32),
        ("frag", ICMPFrag),
        ("raw", ctypes.c_uint32),
    ]


class ICMPHeader(ctypes.Structure):
    """Maps to ICMPHeader_t. Represents the standard ICMP segment header."""
    _pack_ = 1
    _fields_ = [
        ("type", 		ctypes.c_uint8),
        ("code", 		ctypes.c_uint8),
        ("cksum", 		ctypes.c_uint16),
        ("rest",		ICMPRest)
    ]