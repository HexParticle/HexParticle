# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

import PyQt6.QtWidgets as widgets
from PyQt6 import QtCore

# hexp
from hexlib.protocols import TCPHeader, tcp

import typing

class TCPDissectorComponent:
    @staticmethod
    def dissect(parent_node, tcp_header: TCPHeader, _previous_node = None):
        """Adds TCP details to the tree."""
        tcp_item = widgets.QTreeWidgetItem(parent_node, ["Transmission Control Protocol"])
        
        widgets.QTreeWidgetItem(tcp_item, ["Source Port", str(tcp_header.sport)])
        widgets.QTreeWidgetItem(tcp_item, ["Destination Port", str(tcp_header.dport)])
        widgets.QTreeWidgetItem(tcp_item, ["Sequence Number", str(tcp_header.seq)])
        widgets.QTreeWidgetItem(tcp_item, ["Acknowledgment Number", str(tcp_header.ack)])
        widgets.QTreeWidgetItem(tcp_item, ["Window Size", str(tcp_header.win)])
        
        flag_val = tcp_header.flags
        active_flags = [name for mask, name in tcp.FLAG_MEANING.items() if flag_val & mask]
        flag_str = f"0x{flag_val:02x} ({', '.join(active_flags)})"
        
        flag_node = widgets.QTreeWidgetItem(tcp_item, ["Flags", flag_str])
        for mask, name in tcp.FLAG_MEANING.items():
            state = "Set" if flag_val & mask else "Not set"
            widgets.QTreeWidgetItem(flag_node, [f"... {name}", state])

        TCPDissectorComponent.dissect_options(tcp_item, tcp_header)
        return tcp_item

    
    @staticmethod
    def dissect_options(tcp_node, tcp_header: TCPHeader):
        opts_len = tcp_header.header_length - 20
        option_item = widgets.QTreeWidgetItem(tcp_node, ["Options", f"({opts_len} bytes)"])

        if tcp_header.nop():
            widgets.QTreeWidgetItem(option_item, ["NO_OPERATION"])

        mss = tcp_header.mss()
        if mss:
            widgets.QTreeWidgetItem(option_item, ["Maximum Segment Size", str(mss)])

        ws = tcp_header.window_scale()
        if ws:
            widgets.QTreeWidgetItem(option_item, ["Window Scale", str(ws)])

        sack_perm = tcp_header.sack_premitted()
        if sack_perm:
            widgets.QTreeWidgetItem(option_item, ["SACK permitted", str(sack_perm)])

        sack = tcp_header.sack()
        if sack:
            widgets.QTreeWidgetItem(option_item, ["SACK", str(sack)])

        ts = tcp_header.timestamps()
        if ts:
            widgets.QTreeWidgetItem(option_item, ["Timestamps", str(ts)])


class TCPSessionAssemblyWindow(widgets.QWidget):
    def __init__(self, session: typing.List[TCPHeader]):
        super().__init__()
        self.session = session
        self.setWindowTitle("TCP Session Segment List")
        self.resize(500, 400)

        layout = widgets.QVBoxLayout(self)

        self.table = widgets.QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels([
            "Source Port", "Dest Port", "Seq Number", "Ack Number", "Flags", "Win Size"
        ])
        
        self.table.horizontalHeader().setSectionResizeMode(widgets.QHeaderView.ResizeMode.Stretch)
        self.table.setEditTriggers(widgets.QAbstractItemView.EditTrigger.NoEditTriggers)

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
                self.decode_flags(header.flags_str),
                str(header.win)
            ]

            for col, value in enumerate(data):
                item = widgets.QTableWidgetItem(value)
                item.setTextAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
                self.table.setItem(row, col, item)

            if header.flags_str & 0x08: 
                for col in range(6):
                    self.table.item(row, col).setBackground(QtCore.Qt.GlobalColor.lightGray)
