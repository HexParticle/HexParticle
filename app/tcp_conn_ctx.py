# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

import typing

import hex.protocols as protocols

class TcpState(typing.NamedTuple):
    src_host: str
    dst_host: str
    src_port: int
    dst_port: int


class TCPConnectionCtx:
    def __init__(self):
        self.__conns: typing.Dict[TcpState, typing.List] = {}

    
    def manage_tcp_packet(self, ip: protocols.IPV4Header, tcp: protocols.TCPHeader):
        src_host = '.'.join(str(b) for b in ip.src)
        src_port = int(tcp.sport)

        dst_host = '.'.join(str(b) for b in ip.dst)
        dst_port = int(tcp.dport)

        state = TcpState(src_host, dst_host, src_port, dst_port)
        stream_key = self.gen_tcp_stream_key(state)

        conn = self.__conns.get(stream_key)
        if conn:
            self.__conns[stream_key].append(tcp)
        else:
            self.__conns[stream_key] = [tcp]

        return stream_key

    
    def get_conn(self, stream_key) -> typing.List:
        return self.__conns.get(stream_key)


    def is_conn_open(self, stream_key):
        return self.__conns.get(stream_key) is not None


    def gen_tcp_stream_key(self, tcp_state: TcpState):
        endpoint1 = (tcp_state.src_host, tcp_state.src_port)
        endpoint2 = (tcp_state.dst_host, tcp_state.dst_port)
    
        return tuple(sorted((endpoint1, endpoint2)))
