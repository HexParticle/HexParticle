# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

import PyQt6.QtWidgets as widgets

class IPV6DissectorComponent:
    @staticmethod
    def dissect(parent_node, ip_header):
        ver = ip_header.ver_tc_fl >> 28
        tc = (ip_header.ver_tc_fl >>  20) & 0xFF
        fl = ip_header.ver_tc_fl & 0x14

        ip_item = widgets.QTreeWidgetItem(parent_node, ["Internet Protocol Version 6"])
        
        widgets.QTreeWidgetItem(ip_item, ["Version", str(ver)])
        widgets.QTreeWidgetItem(ip_item, ["Traffic Class", str(tc)])
        widgets.QTreeWidgetItem(ip_item, ["Flow Label", str(fl)])

        widgets.QTreeWidgetItem(ip_item, ["Protocol", str(ip_header.proto)])
        widgets.QTreeWidgetItem(ip_item, ["Total Length", str(ip_header.len)])

        ip_item.setExpanded(False)