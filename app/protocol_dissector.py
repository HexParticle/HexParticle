# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

# hexp
from hexlib import protocols as proto
from hexlib.packet import DissectedPacket

import dissectors
import tcp_conn_ctx as tcpcon

# qt
import PyQt6.QtWidgets as widgets

# stdlib
import typing


class ProtocolDissector(widgets.QWidget):
    def __init__(self):
        super().__init__()

        # reassembling TCP segments
        self.tcp_conns: tcpcon.TCPConnectionCtx = tcpcon.TCPConnectionCtx()

        self.layout = widgets.QVBoxLayout(self)
        
        self.current_session_key = None
        self.session_windows = [] # keeping references so windows don't close immediately

        self.button_layout = widgets.QHBoxLayout()
        self.session_btn = widgets.QPushButton("Follow TCP Stream")
        self.session_btn.setEnabled(False)
        self.session_btn.clicked.connect(self.on_session_button_clicked)
        self.button_layout.addWidget(self.session_btn)
        self.button_layout.addStretch()
        self.layout.addLayout(self.button_layout)

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


    def display_packet(self, dissected_pack: DissectedPacket):
        self.tree.clear()
        self.current_session_key = None
        self.session_btn.setEnabled(False)
        
        previous_node = None
        __layer_ip_packet = None
         
        for layer in dissected_pack:
            if isinstance(layer, proto.IPV4Header):
                __layer_ip_packet = layer

            if __layer_ip_packet is not None and isinstance(layer, proto.TCPHeader): # trace only ipv4
                self.current_session_key = self.tcp_conns.manage_tcp_packet(__layer_ip_packet, layer)
                self.session_btn.setEnabled(True)

            dissec_handler = self.dissection_handlers.get(type(layer))
            if dissec_handler:
                previous_node = dissec_handler(self.tree, layer, previous_node)


    def on_session_button_clicked(self):
        if self.current_session_key and self.tcp_conns.is_conn_open(self.current_session_key):
            session_data = self.tcp_conns.get_conn(self.current_session_key)
            self.display_tcp_session_window(session_data)


    def display_tcp_session_window(self, session: typing.List[proto.TCPHeader]):
        window = dissectors.TCPSessionAssemblyWindow(session)
        self.session_windows.append(window)
        window.show()