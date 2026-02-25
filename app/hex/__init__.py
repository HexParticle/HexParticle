# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

import typing

def mac_to_str(bytes: bytearray) -> str:
	if len(bytes) != 6:
		raise ValueError("length must be 6")
	
	return ":".join(map(hex, bytes)).replace("0x", "")
    
def ip_to_str(octets: typing.List[int]) -> str:
	if len(octets) != 4:
		raise ValueError("length must be 4")

	return ".".join(map(str, octets))