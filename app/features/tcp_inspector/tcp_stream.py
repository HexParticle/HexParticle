# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

from typing import List, Tuple, Dict, Set
from dataclasses import dataclass

from hexlib.protocol import tcp, ip
from hexlib import ParsedPacket


@dataclass(frozen=True, order=True)
class Endpoint:
    host: str
    port: int


EndpointPair = Tuple[Endpoint, Endpoint]

TcpStreamKey = EndpointPair

TcpStream = List[tcp.TCPHeader]


class TcpStreamContext:
    def __init__(self):
        self.__conns: Dict[TcpStreamKey, List[tcp.TCPHeader]] = {}
        self.__stream_keys: Set[TcpStreamKey] = set()

    
    def track_packet(self, pp: ParsedPacket) -> TcpStreamKey:
        if not pp.is_tcp_packet():
            raise Exception(f"{pp} is not a TCP packet")
        
        ip = pp.get_ip_layer()
        tcp = pp.get_tcp_layer()
        return self.__create_or_update_tcp_stream(ip, tcp)


    def __create_or_update_tcp_stream(self, ip_hdr: ip.AnyIPHeader, tcp_hdr: tcp.TCPHeader) -> TcpStreamKey:
        stream_key = gen_tcp_stream_key(ip_hdr, tcp_hdr)
        self.__stream_keys.add(stream_key)

        if stream_key not in self.__conns:
            print("Create new stream key: ", stream_key)
            self.__conns[stream_key] = []
        
        self.__conns[stream_key].append(tcp_hdr)
        return stream_key

    
    def get_stream(self, stream_key: TcpStreamKey) -> TcpStream:
        return self.__conns.get(stream_key)

    
    def contains_stream_key(self, stream_key: TcpStreamKey) -> bool:
        return self.__conns.get(stream_key) is not None


    def is_stream_open(self, stream_key: TcpStreamKey):
        return self.contains_stream_key(stream_key)


# Generate a stream key
def gen_tcp_stream_key(ip_hdr: ip.AnyIPHeader, tcp_hdr: tcp.TCPHeader) -> TcpStreamKey:
    if isinstance(ip_hdr, ip.IPV4Header):
        src_host = '.'.join(str(b) for b in ip_hdr.src)
        dst_host = '.'.join(str(b) for b in ip_hdr.dst)
    elif isinstance(ip_hdr, ip.IPV6Header):
        src_host = ':'.join(f'{b:02x}' for b in ip_hdr.src)
        dst_host = ':'.join(f'{b:02x}' for b in ip_hdr.dst)

    src_port = int(tcp_hdr.sport)
    dst_port = int(tcp_hdr.dport)

    endpoint1 = Endpoint(src_host, src_port)
    endpoint2 = Endpoint(dst_host, dst_port)
    return tuple(sorted((endpoint1, endpoint2)))