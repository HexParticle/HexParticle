# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

import PyQt6.QtWidgets as widgets

from hex import protocols as protos, icmp

class ICMPDissectorComponent:
    @staticmethod
    def dissect(parent_node, icmp_header):
        """Adds ICMP details to the tree."""
        icmp_item = widgets.QTreeWidgetItem(parent_node, [f"Internet Control Message Protocol"])

        type_msg = icmp.icmp_type_meaning(icmp_header.type)
        icmp_type = f"{icmp_header.type} {'' if type_msg is None else f'({type_msg})'}"
        widgets.QTreeWidgetItem(icmp_item, ["Type", icmp_type])

        code_msg = icmp.icmp_meaning(icmp_header.type, icmp_header.code)
        icmp_code = f"{icmp_header.code} {'' if code_msg is None else f'({code_msg})'}"
        widgets.QTreeWidgetItem(icmp_item, ["Code", icmp_code])

        widgets.QTreeWidgetItem(icmp_item, ["Checksum", str(icmp_header.cksum)])
        icmp_item.setExpanded(True)