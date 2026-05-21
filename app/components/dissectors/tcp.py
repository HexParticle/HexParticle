# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

from  PyQt6 import QtWidgets

# hexp
from hexlib.protocol import tcp

class TCPDissectorComponent:
    @staticmethod
    def dissect(parent_node, tcp_header: tcp.TCPHeader, _previous_node = None):
        """Adds TCP details to the tree."""
        tcp_item = QtWidgets.QTreeWidgetItem(parent_node, ["Transmission Control Protocol"])
        
        QtWidgets.QTreeWidgetItem(tcp_item, ["Source Port", str(tcp_header.sport)])
        QtWidgets.QTreeWidgetItem(tcp_item, ["Destination Port", str(tcp_header.dport)])
        QtWidgets.QTreeWidgetItem(tcp_item, ["Sequence Number", str(tcp_header.seq)])
        QtWidgets.QTreeWidgetItem(tcp_item, ["Acknowledgment Number", str(tcp_header.ack)])
        QtWidgets.QTreeWidgetItem(tcp_item, ["Window Size", str(tcp_header.win)])
        
        flag_val = tcp_header.flags
        active_flags = [name for mask, name in tcp.FLAG_MEANING.items() if flag_val & mask]
        flag_str = f"0x{flag_val:02x} ({', '.join(active_flags)})"
        
        flag_node = QtWidgets.QTreeWidgetItem(tcp_item, ["Flags", flag_str])
        for mask, name in tcp.FLAG_MEANING.items():
            state = "Set" if flag_val & mask else "Not set"
            QtWidgets.QTreeWidgetItem(flag_node, [f"... {name}", state])

        TCPDissectorComponent.dissect_options(tcp_item, tcp_header)
        return tcp_item

    
    @staticmethod
    def dissect_options(tcp_node, tcp_header: tcp.TCPHeader):
        opts_len = tcp_header.header_length - 20
        option_item = QtWidgets.QTreeWidgetItem(tcp_node, ["Options", f"({opts_len} bytes)"])

        if tcp_header.nop():
            QtWidgets.QTreeWidgetItem(option_item, ["NO_OPERATION"])

        mss = tcp_header.mss()
        if mss:
            QtWidgets.QTreeWidgetItem(option_item, ["Maximum Segment Size", str(mss)])

        ws = tcp_header.window_scale()
        if ws:
            QtWidgets.QTreeWidgetItem(option_item, ["Window Scale", str(ws)])

        sack_perm = tcp_header.sack_premitted()
        if sack_perm:
            QtWidgets.QTreeWidgetItem(option_item, ["SACK permitted", str(sack_perm)])

        sack = tcp_header.sack()
        if sack:
            QtWidgets.QTreeWidgetItem(option_item, ["SACK", str(sack)])

        ts = tcp_header.timestamps()
        if ts:
            QtWidgets.QTreeWidgetItem(option_item, ["Timestamps", str(ts)])