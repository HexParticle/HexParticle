# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

from PyQt6 import QtCore

import queue
from typing import Callable

from hexlib import ParsedPacket
from features.tcp_inspector import TcpStreamContext

PacketHandler = Callable[[ParsedPacket], None]

class PacketProcessorThread(QtCore.QThread):
    packet_processed = QtCore.pyqtSignal(object)


    def __init__(self, tcp_ctx: TcpStreamContext):
        super().__init__()

        self.tcp_ctx = tcp_ctx

        self.queue: queue.Queue[ParsedPacket | None] = queue.Queue()

    
    '''
    The callable `cb` is run for every captured packet.
    '''
    def on_packet_processed(self, cb: PacketHandler):
        if cb is None: return

        self.packet_processed.connect(cb)


    '''
    Enqueue a parsed packet for processing.
    '''
    def enqueue(self, pp: ParsedPacket):
        self.queue.put(pp)


    '''
    Start the thread.
    '''
    def run(self):
        while not self.isInterruptionRequested():
            pp = self.queue.get() 

            if pp is None: continue

            processed = self.__process_incoming_packet(pp)
            self.packet_processed.emit(processed)

    
    def __process_incoming_packet(self, pp: ParsedPacket) -> ParsedPacket:
        if pp.is_tcp_packet():
            stream_key = self.tcp_ctx.track_packet(pp)
            if stream_key is None:
                print("Failed to generate TCP stream key!")

        return pp


    def stop(self):
        self.requestInterruption()
        self.queue.put(None)