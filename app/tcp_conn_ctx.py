# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

import typing

from hexlib.protocol import tcp, ip

class TCPConnectionCtx:
    def __init__(self):
        self.__conns: typing.Dict[tuple, typing.List] = {}

    
    def manage_tcp_packet(self, ip: ip.IPV4Header, tcp: tcp.TCPHeader):
        src_host = '.'.join(str(b) for b in ip.src)
        src_port = int(tcp.sport)

        dst_host = '.'.join(str(b) for b in ip.dst)
        dst_port = int(tcp.dport)

        stream_key = self.gen_tcp_stream_key(src_host, src_port, dst_host, dst_port)

        if stream_key not in self.__conns:
            self.__conns[stream_key] = []
        
        self.__conns[stream_key].append(tcp)
        return stream_key

    
    def get_conn(self, stream_key) -> typing.List:
        return self.__conns.get(stream_key)


    def is_conn_open(self, stream_key):
        return self.__conns.get(stream_key) is not None


    def gen_tcp_stream_key(self, src_host, src_port, dst_host, dst_port):
        endpoint1 = (src_host, src_port)
        endpoint2 = (dst_host, dst_port)
    
        return tuple(sorted((endpoint1, endpoint2)))
