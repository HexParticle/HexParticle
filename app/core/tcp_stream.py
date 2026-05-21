# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

import typing

from hexlib.protocol import tcp, ip
from hexlib import ParsedPacket

class TCPStreamContext:
    def __init__(self):
        self.__conns: typing.Dict[tuple, typing.List[tcp.TCPHeader]] = {}

    
    def track_packet(self, pp: ParsedPacket):
        if not pp.is_tcp_packet():
            raise Exception(f"{pp} is not a TCP packet")
        
        ip = pp.get_ip_layer()
        tcp = pp.get_tcp_layer()
        return self._create_or_update_tcp_stream(ip, tcp)


    def _create_or_update_tcp_stream(self, ip_hdr: ip.AnyIPHeader, tcp_hdr: tcp.TCPHeader):
        if isinstance(ip_hdr, ip.IPV4Header):
            src_host = '.'.join(str(b) for b in ip_hdr.src)
            dst_host = '.'.join(str(b) for b in ip_hdr.dst)
        elif isinstance(ip_hdr, ip.IPV6Header):
            src_host = ':'.join(f'{b:02x}' for b in ip_hdr.src)
            dst_host = ':'.join(f'{b:02x}' for b in ip_hdr.dst)

        src_port = int(tcp_hdr.sport)
        dst_port = int(tcp_hdr.dport)
        stream_key = self.gen_tcp_stream_key(src_host, src_port, dst_host, dst_port)

        if stream_key not in self.__conns:
            self.__conns[stream_key] = []
        
        self.__conns[stream_key].append(tcp_hdr)
        return stream_key

    
    def get_stream(self, stream_key) -> typing.List[tcp.TCPHeader]:
        return self.__conns.get(stream_key)


    def is_stream_open(self, stream_key):
        return self.__conns.get(stream_key) is not None


    def gen_tcp_stream_key(self, src_host, src_port, dst_host, dst_port):
        endpoint1 = (src_host, src_port)
        endpoint2 = (dst_host, dst_port)
        return tuple(sorted((endpoint1, endpoint2)))
