# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

import PyQt6.QtWidgets as widgets

class TCPDissectorComponent:
    FLAGS = {
        0x01: "FIN", 0x02: "SYN", 0x04: "RST", 
        0x08: "PSH", 0x10: "ACK", 0x20: "URG"
    }

    @staticmethod
    def dissect(parent_node, tcp_header):
        """Adds TCP details to the tree."""
        tcp_item = widgets.QTreeWidgetItem(parent_node, ["Transmission Control Protocol"])
        
        widgets.QTreeWidgetItem(tcp_item, ["Source Port", str(tcp_header.sport)])
        widgets.QTreeWidgetItem(tcp_item, ["Destination Port", str(tcp_header.dport)])
        widgets.QTreeWidgetItem(tcp_item, ["Sequence Number", str(tcp_header.seq)])
        widgets.QTreeWidgetItem(tcp_item, ["Acknowledgment Number", str(tcp_header.ack)])
        widgets.QTreeWidgetItem(tcp_item, ["Window Size", str(tcp_header.win)])
        
        flag_val = tcp_header.flags
        active_flags = [name for mask, name in TCPDissectorComponent.FLAGS.items() if flag_val & mask]
        flag_str = f"0x{flag_val:02x} ({', '.join(active_flags)})"
        
        flag_node = widgets.QTreeWidgetItem(tcp_item, ["Flags", flag_str])
        for mask, name in TCPDissectorComponent.FLAGS.items():
            state = "Set" if flag_val & mask else "Not set"
            widgets.QTreeWidgetItem(flag_node, [f"... {name}", state])
            
        tcp_item.setExpanded(True)