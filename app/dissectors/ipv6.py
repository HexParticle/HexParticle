# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

import PyQt6.QtWidgets as widgets

from hex import ip, protocols as protos, ipv6_to_str

class IPV6DissectorComponent:
    @staticmethod
    def dissect(parent_node, ip_header, previous_node = None):
        ver = ip_header.ver_tc_fl >> 28
        tc = (ip_header.ver_tc_fl >>  20) & 0xFF
        fl = ip_header.ver_tc_fl & 0x14

        ip_item = widgets.QTreeWidgetItem(parent_node, ["Internet Protocol Version 6"])
        next_hdr = ip.IP_PROTOCOL_NAMES.get(ip_header.next_hdr)
        next_hdr = str(ip_header.next_hdr) + (" (" + next_hdr + ")" if next_hdr else f"{ip_header.next_hdr} (Unknown next header type)")
        
        widgets.QTreeWidgetItem(ip_item, ["Source", ipv6_to_str(ip_header.src)])
        widgets.QTreeWidgetItem(ip_item, ["Destination", ipv6_to_str(ip_header.dst)])
        widgets.QTreeWidgetItem(ip_item, ["Version", str(ver)])
        widgets.QTreeWidgetItem(ip_item, ["Traffic Class", str(tc)])
        widgets.QTreeWidgetItem(ip_item, ["Flow Label", str(fl)])

        widgets.QTreeWidgetItem(ip_item, ["Next Header", next_hdr])
        widgets.QTreeWidgetItem(ip_item, ["Total Length", str(ip_header.len)])

        ip_item.setExpanded(False)
        return ip_item


class IPV6ExtDissectorComponent:
    @staticmethod
    def dissect(parent_node, ext_header, previous_node = None):
        next_hdr = ip.IP_PROTOCOL_NAMES.get(ext_header.next_hdr)
        ext_item = widgets.QTreeWidgetItem(parent_node, next_hdr)
        ext_item.setExpanded(False)

        return ext_item