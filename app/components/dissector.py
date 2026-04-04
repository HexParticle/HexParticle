# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

# hexp
from hexlib import protocol as proto
from hexlib import ParsedPacket

from components import dissectors

# qt
import PyQt6.QtWidgets as widgets

# stdlib
import typing

class ProtocolDissector(widgets.QWidget):
    def __init__(self):
        super().__init__()

        self.layout = widgets.QVBoxLayout(self)

        self.tree = widgets.QTreeWidget()
        self.tree.setHeaderLabels(["Field", "Value"])
        self.tree.setColumnWidth(0, 200)
        self.layout.addWidget(self.tree)

        self.dissection_handlers = {
            proto.TCPHeader:       dissectors.TCPDissectorComponent.dissect,
            proto.IPV4Header:      dissectors.IPV4DissectorComponent.dissect,
            proto.ARPHeader:       dissectors.ARPDissectorComponent.dissect,
            proto.EtherHeader:     dissectors.EthernetDissectorComponent.dissect,
            proto.UDPHeader:       dissectors.UDPDissectorComponent.dissect,
            proto.IPV6Header:      dissectors.IPV6DissectorComponent.dissect,
            proto.ICMPHeader:      dissectors.ICMPDissectorComponent.dissect,
        }


    def display_packet(self, dissected_pack: ParsedPacket):
        self.tree.clear()
        previous_node = None
         
        for layer in dissected_pack:
            dissec_handler = self.dissection_handlers.get(type(layer))
            if dissec_handler:
                previous_node = dissec_handler(self.tree, layer, previous_node)


    def display_tcp_session_window(self, session: typing.List[proto.TCPHeader]):
        window = dissectors.TCPSessionAssemblyWindow(session)
        self.session_windows.append(window)
        window.show()