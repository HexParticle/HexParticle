# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

import PyQt6.QtWidgets as widgets

from hex import protocols as protos, mac_to_str

class UDPDissectorComponent:
    @staticmethod
    def dissect(parent_node, udp_header):
        udp_item = widgets.QTreeWidgetItem(parent_node, ["User Datagram Protocol"])
        widgets.QTreeWidgetItem(udp_item, ["Source Port", str(udp_header.sport)])

        port_info = protos.COMMON_PORTS.get(udp_header.dport, "")
        widgets.QTreeWidgetItem(udp_item, ["Destination Port", f"{udp_header.dport} {port_info}"])

        widgets.QTreeWidgetItem(udp_item, ["Length", f"{udp_header.length} bytes"])
        widgets.QTreeWidgetItem(udp_item, ["Checksum", f"0x{udp_header.cksum:04x}"])
        udp_item.setExpanded(True)