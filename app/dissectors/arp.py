# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

import PyQt6.QtWidgets as widgets

from hex import protocols as protos

class ARPDissectorComponent:
    @staticmethod
    def dissect(parent_node, arp_header):
        """Adds ARP details to the tree."""
        arp_type = "Reply" if arp_header.op == protos.ARP_RESPONSE else "Request"
        arp_item = widgets.QTreeWidgetItem(parent_node, [f"Address Resolution Protocol ({arp_type})"])

        proto_name = protos.ETHER_TYPE_NAMES.get(arp_header.ptype)

        widgets.QTreeWidgetItem(arp_item, ["Hardware Type", str(arp_header.htype)])
        widgets.QTreeWidgetItem(arp_item, ["Protocol Type", str(proto_name) + f" ({hex(arp_header.ptype)})"])
        widgets.QTreeWidgetItem(arp_item, ["Hardware Length", hex(arp_header.hlen)])
        widgets.QTreeWidgetItem(arp_item, ["Protocol Length", hex(arp_header.plen)])
        widgets.QTreeWidgetItem(arp_item, ["Opcode", f"{arp_type} ({hex(arp_header.op)})"])
        widgets.QTreeWidgetItem(arp_item, ["Sender MAC Address", ARPDissectorComponent.to_mac_str(arp_header.sha)])
        widgets.QTreeWidgetItem(arp_item, ["Sender Protocol Address", ARPDissectorComponent.to_ip_str(arp_header.spa)])
        widgets.QTreeWidgetItem(arp_item, ["Target MAC Address", ARPDissectorComponent.to_mac_str(arp_header.tha)])
        widgets.QTreeWidgetItem(arp_item, ["Target Protocol Address", ARPDissectorComponent.to_ip_str(arp_header.tpa)])
        arp_item.setExpanded(True)


    def to_mac_str(bytes):
        return ":".join(map(hex, bytes)).replace("0x", "")

    
    def to_ip_str(octets):
        return ".".join(map(str, octets))