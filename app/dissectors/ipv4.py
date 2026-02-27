# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

import PyQt6.QtWidgets as widgets

class IPV4DissectorComponent:
    @staticmethod
    def dissect(parent_node, ip_header, _previous_node = None):
        flags = ip_header.flags_off >> 13
        offset = ip_header.flags_off & 0x1FFF

        df = (flags & 0x2) >> 1 # don't fragment
        mf = flags & 0x1 # more fragments

        """Adds IPV4 details to the tree."""
        ip_item = widgets.QTreeWidgetItem(parent_node, ["Internet Protocol Version 4"])
        widgets.QTreeWidgetItem(ip_item, ["Version/IHL", hex(ip_header.ver_ihl)])
        widgets.QTreeWidgetItem(ip_item, ["Total Length", str(ip_header.len)])
        widgets.QTreeWidgetItem(ip_item, ["Identification", hex(ip_header.id)])

        flag_node = widgets.QTreeWidgetItem(ip_item, ["Flags", hex(flags)])
        widgets.QTreeWidgetItem(flag_node, ["...Reserved Bit", "Not Set"])

        df_text = "Set" if df == 0x1 else "Not Set"
        widgets.QTreeWidgetItem(flag_node, ["...Don't Fragment", df_text])
        
        mf_text = "Set" if mf == 0x1 else "Not Set"
        widgets.QTreeWidgetItem(flag_node, ["...More Fragments", mf_text])

        widgets.QTreeWidgetItem(ip_item, ['Fragment Offset', hex(offset)])
        widgets.QTreeWidgetItem(ip_item, ["TTL", str(ip_header.ttl)])
        widgets.QTreeWidgetItem(ip_item, ["Protocol", str(ip_header.proto)])
        widgets.QTreeWidgetItem(ip_item, ["Source", ".".join(map(str, ip_header.src))])
        widgets.QTreeWidgetItem(ip_item, ["Destination", ".".join(map(str, ip_header.dst))])

        ip_item.setExpanded(False)
        return ip_item