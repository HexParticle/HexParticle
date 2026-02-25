# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

import PyQt6.QtWidgets as widgets

class IPV4DissectorComponent:
    @staticmethod
    def dissect(parent_node, ip_header):
        flags = ip_header.flags_off >> 13
        offset = ip_header.flags_off & 0x1FFF

        df = (flags & 0x2) >> 1 # don't fragment
        mf = flags & 0x1 # more fragments

        """Adds IPV4 details to the tree."""
        parent = widgets.QTreeWidgetItem(parent_node, ["Internet Protocol Version 4"])
        widgets.QTreeWidgetItem(parent, ["Version/IHL", hex(ip_header.ver_ihl)])
        widgets.QTreeWidgetItem(parent, ["Total Length", str(ip_header.len)])
        widgets.QTreeWidgetItem(parent, ["Identification", hex(ip_header.id)])

        flag_node = widgets.QTreeWidgetItem(parent, ["Flags", hex(flags)])
        widgets.QTreeWidgetItem(flag_node, ["...Reserved Bit", "Not Set"])

        df_text = "Set" if df == 0x1 else "Not Set"
        widgets.QTreeWidgetItem(flag_node, ["...Don't Fragment", df_text])
        
        mf_text = "Set" if mf == 0x1 else "Not Set"
        widgets.QTreeWidgetItem(flag_node, ["...More Fragments", mf_text])

        widgets.QTreeWidgetItem(parent, ['Fragment Offset', hex(offset)])
        widgets.QTreeWidgetItem(parent, ["TTL", str(ip_header.ttl)])
        widgets.QTreeWidgetItem(parent, ["Protocol", str(ip_header.proto)])
        widgets.QTreeWidgetItem(parent, ["Source", ".".join(map(str, ip_header.src))])
        widgets.QTreeWidgetItem(parent, ["Destination", ".".join(map(str, ip_header.dst))])
        parent.setExpanded(False)