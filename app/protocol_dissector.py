# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

# hexp
from hex import protocols as protos
from transport_layer import FragmentKey, generate_stream_key

import dissectors

# qt
import PyQt6.QtWidgets as widgets

# stdlib
import typing


class ProtocolDissector(widgets.QWidget):
    def __init__(self):
        super().__init__()


        # reassembling UDP segments
        self.__udp_segments: typing.Dict[FragmentKey, typing.List] = {}

        # reassembling TCP segments
        self.__tcp_segments: typing.Dict[FragmentKey, typing.List] = {}

        self.layout = widgets.QVBoxLayout(self)
        
        self.current_session_key = None
        self.session_windows = [] # Keep references so windows don't close immediately

        self.button_layout = widgets.QHBoxLayout()
        self.session_btn = widgets.QPushButton("Follow TCP Stream")
        self.session_btn.setEnabled(False) # Disabled until a TCP packet is clicked
        self.session_btn.clicked.connect(self.on_session_button_clicked)
        self.button_layout.addWidget(self.session_btn)
        self.button_layout.addStretch()
        self.layout.addLayout(self.button_layout)

        self.tree = widgets.QTreeWidget()
        self.tree.setHeaderLabels(["Field", "Value"])
        self.tree.setColumnWidth(0, 200)
        self.layout.addWidget(self.tree)

        self.dissection_handlers = {
            protos.TCPHeader:       dissectors.TCPDissectorComponent.dissect,
            protos.IPV4Header:      dissectors.IPV4DissectorComponent.dissect,
            protos.ARPHeader:       dissectors.ARPDissectorComponent.dissect,
            protos.EtherHeader:     dissectors.EthernetDissectorComponent.dissect,
            protos.UDPHeader:       dissectors.UDPDissectorComponent.dissect,
            protos.IPV6Header:      dissectors.IPV6ExtDissectorComponent.dissect,
            protos.ICMPHeader:      dissectors.ICMPDissectorComponent.dissect,
            # protos.IPV6ExtHeader:   dissectors.IPV6ExtDissectorComponent.dissect
        }


    def add_new_tcp_segment(self, seg_key, value):
        session = self.__tcp_segments.get(seg_key)
        if session:
            session.append(value)
        else:
            self.__tcp_segments[seg_key] = [value]


    def generate_tcp_stream_key(self, ip_packet, tcp_packet):
        return generate_stream_key(
            ip_packet.src,
            tcp_packet.sport,
            ip_packet.dst,
            tcp_packet.dport
        )


    def display_packet(self, pwrapper):
        self.tree.clear()
        self.current_session_key = None
        self.session_btn.setEnabled(False)
        
        previous_node = None
        __layer_ip_packet = None
         
        for layer in pwrapper.layers:
            if isinstance(layer, protos.IPV4Header) or isinstance(layer, protos.IPV6Header):
                __layer_ip_packet = layer

            if isinstance(layer, protos.TCPHeader):
                self.current_session_key = self.generate_tcp_stream_key(__layer_ip_packet, layer)
                
                self.add_new_tcp_segment(self.current_session_key, layer)

                self.session_btn.setEnabled(True)

            dissec_handler = self.dissection_handlers.get(type(layer))
            if dissec_handler:
                previous_node = dissec_handler(self.tree, layer, previous_node)

    def on_session_button_clicked(self):
        """Triggered when user wants to see the full list of segments for the current flow."""
        if self.current_session_key and self.current_session_key in self.__tcp_segments:
            session_data = self.__tcp_segments[self.current_session_key]
            self.display_tcp_session_window(session_data)

    def display_tcp_session_window(self, session: typing.List[protos.TCPHeader]):
        window = dissectors.TCPSessionAssemblyWindow(session)
        self.session_windows.append(window)
        window.show()
