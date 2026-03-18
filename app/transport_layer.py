# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

import typing

class FragmentKey(typing.NamedTuple):
    src_host: str
    dst_host: str
    src_port: int
    dst_port: int


def generate_stream_key(src_ip, src_port, dst_ip, dst_port):
    s_ip = '.'.join(str(b) for b in src_ip)
    d_ip = '.'.join(str(b) for b in dst_ip)
    print(s_ip, d_ip)
    
    s_port = int(src_port)
    d_port = int(dst_port)
    
    endpoint1 = (s_ip, s_port)
    endpoint2 = (d_ip, d_port)
    
    return tuple(sorted((endpoint1, endpoint2)))
