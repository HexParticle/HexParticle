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
    

# reassembling UDP segments
__udp_segments: typing.Dict[FragmentKey, typing.List] = {}

# reassembling TCP segments
__tcp_segments: typing.Dict[FragmentKey, typing.List] = {}


def generate_tcp_stream_key(ip_packet, tcp_packet):
    return generate_stream_key(
       ip_packet.src,
       ip_packet.dst,
       tcp_packet.sport,
       tcp_packet.dport
    )


def __add_new_tcp_segment(seg_key, value):
    session = __tcp_segments.get(seg_key)
    if session:
        session.append(value)
    else:
        __tcp_segments[seg_key] = [value]


class ProtocolDissector(widgets.QWidget):
    def __init__(self):
        super().__init__()
        self.layout = widgets.QVBoxLayout(self)
        
        # Tracking the key for the currently displayed packet
        self.current_session_key = None
        self.session_windows = [] # Keep references so windows don't close immediately

        # Header / Action Bar
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
            protos.IPV6ExtHeader:   dissectors.IPV6ExtDissectorComponent.dissect
        }

    def display_packet(self, pwrapper):
        self.tree.clear()
        self.current_session_key = None
        self.session_btn.setEnabled(False)
        
        previous_node = None
        __layer_ip_packet = None
         
        for layer in pwrapper.layers:
            if isinstance(layer, protos.IPV4Header):
                __layer_ip_packet = layer

            if isinstance(layer, protos.TCPHeader):
                # Calculate the key for this specific packet
                self.current_session_key = generate_tcp_stream_key(__layer_ip_packet, layer)
                
                # Update our global reassembly dict
                __add_new_tcp_segment(self.current_session_key, layer)

                # Enable button only if we have a valid TCP session
                self.session_btn.setEnabled(True)

            dissec_handler = self.dissection_handlers.get(type(layer))
            if dissec_handler:
                previous_node = dissec_handler(self.tree, layer, previous_node)

    def on_session_button_clicked(self):
        """Triggered when user wants to see the full list of segments for the current flow."""
        if self.current_session_key and self.current_session_key in __tcp_segments:
            session_data = __tcp_segments[self.current_session_key]
            self.display_tcp_session_window(session_data)

    def display_tcp_session_window(self, session: typing.List[protos.TCPHeader]):
        # We store the window in a list to prevent Python's garbage collector 
        # from destroying it as soon as the function ends.
        window = dissectors.TCPSessionAssemblyWindow(session)
        self.session_windows.append(window)
        window.show()