# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

import typing

class FragmentKey(typing.NamedTuple):
    src_host: str
    dst_host: str
    src_port: int
    dst_port: int


def generate_stream_key(src_ip, src_port, dst_ip, dst_port):
    endpoint1 = (src_ip, src_port)
    endpoint2 = (dst_ip, dst_port)
    
    return tuple(sorted((endpoint1, endpoint2)))