# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

import typing
from hexlib.protocol import tcp

from PyQt6 import QtWidgets, QtCore

class TcpSessionAssemblyWindow(QtWidgets.QWidget):
    def __init__(self, session: typing.List[tcp.TCPHeader]):
        super().__init__()
        self.session = session
        self.setWindowTitle("TCP Reassembler")
        self.resize(500, 400)

        layout = QtWidgets.QVBoxLayout(self)

        self.table = QtWidgets.QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels([
            "Source Port", "Dest Port", "Seq Number", "Ack Number", "Flags", "Win Size"
        ])
        
        self.table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeMode.Stretch)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)

        self.populate_table()
        layout.addWidget(self.table)


    def decode_flags(self, flags_byte: int) -> str:
        active_flags = [name for bit, name in tcp.FLAG_MEANING.items() if flags_byte & bit]
        return " | ".join(active_flags) if active_flags else "None"


    def populate_table(self):
        self.table.setRowCount(len(self.session))
        
        for row, header in enumerate(self.session):
            data = [
                str(header.sport),
                str(header.dport),
                str(header.seq),
                str(header.ack),
                self.decode_flags(header.flags_num),
                str(header.win)
            ]

            for col, value in enumerate(data):
                item = QtWidgets.QTableWidgetItem(value)
                item.setTextAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
                self.table.setItem(row, col, item)

            if header.flags_num & 0x08: 
                for col in range(6):
                    self.table.item(row, col).setBackground(QtCore.Qt.GlobalColor.lightGray)
