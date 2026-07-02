# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

from PyQt6 import QtCore

from hexlib import HexParticleLib, ParsedPacket

import threading

class PacketCapturerThread(QtCore.QThread):
    packet_captured = QtCore.pyqtSignal(ParsedPacket)

    def __init__(self, hexp: HexParticleLib):
        super().__init__()
        self.running = True
        self.hexp = hexp

        self.pending_filter = None
        self.filter_lock = threading.Lock()

    
    def update_filter(self, new_filter: str):
        with self.filter_lock:
            self.pending_filter = new_filter


    def run(self):
        try:
            while self.running:
                with self.filter_lock:
                    if self.pending_filter is not None:
                        filter_bytes = self.pending_filter.encode('UTF-8')

                        filter_result = self.hexp.apply_filter(filter_bytes)
                        if filter_result is None:
                            print("Failed to apply filters!")
                        
                        self.pending_filter = None

                packet = self.hexp.next_packet()
                if packet:
                    self.packet_captured.emit(packet)
        except Exception as e:
            print(e)


    def stop(self):
        self.running = False