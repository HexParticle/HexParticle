# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

from PyQt6 import QtCore

import queue

from hexlib import ParsedPacket
from features.tcp_inspector import TcpStreamContext

class PacketProcessorThread(QtCore.QThread):
    row_ready = QtCore.pyqtSignal(list)


    def __init__(self, tcp_ctx: TcpStreamContext):
        super().__init__()
        self.tcp_ctx = tcp_ctx
        self.queue = queue.Queue()
        self.running = True


    def enqueue(self, pp: ParsedPacket):
        self.queue.put(pp)


    def run(self):
        while self.running:
            pp = self.queue.get() 

            row = self.build_row(pp)
            self.row_ready.emit(row)


    def build_row(self, pp: ParsedPacket):
        ip = pp.get_ip_layer()
        tcp = pp.get_tcp_layer()

        return [
            str(ip.src),
            str(ip.dst),
            str(tcp.sport),
            str(tcp.dport),
        ]


    def stop(self):
        self.running = False
        self.queue.put(None)