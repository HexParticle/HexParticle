# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

from hex import protocols as protos
import dissectors

from PyQt6.QtWidgets import QTreeWidget, QVBoxLayout, QWidget

class ProtocolDissector(QWidget):
    def __init__(self):
        super().__init__()
        self.layout = QVBoxLayout(self)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Field", "Value"])
        self.tree.setColumnWidth(0, 200)
        self.layout.addWidget(self.tree)

        self.dissection_handlers = {
            protos.TCPHeader: 	dissectors.TCPDissectorComponent.dissect,
            protos.IPV4Header: 	dissectors.IPV4DissectorComponent.dissect,
            protos.ARPHeader: 	dissectors.ARPDissectorComponent.dissect,
            protos.EtherHeader: dissectors.EthernetDissectorComponent.dissect,
            protos.UDPHeader: 	dissectors.UDPDissectorComponent.dissect,
            protos.IPV6Header:	dissectors.IPV6DissectorComponent.dissect
        }


    def display_packet(self, pwrapper):
        """
        Processes the PacketWrapper (which contains the layers 
        parsed from ProtocolNode_t) and populates the tree.
        """
        self.tree.clear()
        
        for layer in pwrapper.layers:
            dissec_handler = self.dissection_handlers.get(type(layer))
            if dissec_handler:
                dissec_handler(self.tree, layer)