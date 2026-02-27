# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

import PyQt6.QtWidgets as widgets

from hex import protocols as protos, mac_to_str

class EthernetDissectorComponent:
    @staticmethod
    def dissect(parent_node, ether_header, _previous_node = None):
        ether_item = widgets.QTreeWidgetItem(parent_node, ["Ethernet II"])

        proto_name = protos.ETHER_TYPE_NAMES.get(ether_header.type)
        widgets.QTreeWidgetItem(ether_item, ["Source Address", mac_to_str(ether_header.src_mac)])
        widgets.QTreeWidgetItem(ether_item, ["Destination Address", mac_to_str(ether_header.dst_mac)])
        widgets.QTreeWidgetItem(ether_item, ["Type", str(proto_name)])
        widgets.QTreeWidgetItem(ether_item, ["Length", hex(ether_header.len)])
        ether_item.setExpanded(False)

        if ether_header.vlan_count > 0:
            EthernetDissectorComponent.dissect_vlan_tags(parent_node, ether_header)

        return ether_item

    @staticmethod
    def dissect_vlan_tags(parent_node, ether_header):
        vlan_item = widgets.QTreeWidgetItem(parent_node, ["802.1Q Virtual LAN"])

        for vlan_tag in ether_header.vlans:
            vlan_id = vlan_tag.tci & 0x0FFF
            vlan_pri = (vlan_tag.tci >> 13) & 0x07
            vlan_dei = (vlan_tag.tci >> 12) & 0x01

            widgets.QTreeWidgetItem(vlan_item, ["Tag Protocol ID", vlan_tag.tpid])
            widgets.QTreeWidgetItem(vlan_item, ["VLAN ID", vlan_id])
            widgets.QTreeWidgetItem(vlan_item, ["Priority Code Point", vlan_pri])
            widgets.QTreeWidgetItem(vlan_item, ["Drop Eligible Indicator", vlan_dei])

        return vlan_item