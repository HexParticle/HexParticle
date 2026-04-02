# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, 
                                    QTableWidget, QTableWidgetItem, QPushButton, QMenu)
from PyQt6.QtCore import QThread, pyqtSignal

import PyQt6.QtWidgets as pyqtw
from  PyQt6 import QtCore

from hexlib.lib_wrapper import HexParticle
from hexlib.packet import DissectedPacket
from hexlib import protocols as proto, ipv6_to_str, ip_to_str, mac_to_str, ip, icmp
from protocol_dissector import ProtocolDissector
from dissectors import HexViewer
import tcp_conn_ctx as tcpcon

import style_loader

class HexParticleWorker(QThread):
    packet_received = pyqtSignal(DissectedPacket)

    def __init__(self, interface):
        super().__init__()
        self.interface = interface
        self.running = True
        self.hexp = HexParticle(interface)


    def run(self):
        try:
            while self.running:
                packet = self.hexp.next_packet()
                if packet:
                    self.packet_received.emit(packet)
            self.hexp.close()
        except Exception as e:
            print(f"Worker Error: {e}")


    def stop(self):
        self.running = False


class InterfaceListener(QWidget):
    def __init__(self, interface: str):
        super().__init__()
        self.worker = None
        self.interface = interface
        self.packets = []

		# the most recent packet
        self.most_recent_packet: DissectedPacket = None

        # the currently selected packet
        self.selected_packet: DissectedPacket = None

        # reassembling TCP segments
        self.tcp_conns: tcpcon.TCPConnectionCtx = tcpcon.TCPConnectionCtx()

        self.init_ui()


    def init_ui(self):
        self.setWindowTitle("HexParticle Sniffer")
        self.resize(1000, 600)
        # self.showFullScreen()
        self.setStyleSheet(style_loader.get_style("./styles/interface_listener.css"))

        layout = QVBoxLayout(self)
        
        self.search_bar = pyqtw.QLineEdit()
        self.search_bar.setPlaceholderText("Filter by Protocol or IP (e.g., TCP, 192.168...)")
        self.search_bar.textChanged.connect(self.filter_table)
        layout.addWidget(self.search_bar)
        
        self.main_splitter = pyqtw.QSplitter(QtCore.Qt.Orientation.Vertical)

        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(5)
        self.packet_table.setHorizontalHeaderLabels(
            ["Source", "Destination", "Protocol", "Length", "Info"]
        )
        self.packet_table.horizontalHeader().setStretchLastSection(True)
        # self.packet_table.setAlternatingRowColors(True)

        self.packet_table.itemClicked.connect(self.on_row_selected)
        self.packet_table.setContextMenuPolicy(QtCore.Qt.ContextMenuPolicy.CustomContextMenu)
        self.packet_table.customContextMenuRequested.connect(self.show_row_context_menu)

        self.main_splitter.addWidget(self.packet_table)

        self.dissector = ProtocolDissector()
        self.hex_viewer = HexViewer()
        
        self.bottom_splitter = pyqtw.QSplitter(QtCore.Qt.Orientation.Horizontal)
        self.bottom_splitter.addWidget(self.dissector)
        self.bottom_splitter.addWidget(self.hex_viewer)
        
        self.main_splitter.addWidget(self.bottom_splitter)

        self.bottom_splitter.setStretchFactor(0, 1)
        self.bottom_splitter.setStretchFactor(1, 1)

        layout.addWidget(self.main_splitter)

        ctrl_layout = QHBoxLayout()
        self.start_btn = QPushButton("Start Capture")
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setEnabled(False)
        
        self.start_btn.clicked.connect(self.start_sniffing)
        self.stop_btn.clicked.connect(self.stop_sniffing)
        
        ctrl_layout.addWidget(self.start_btn)
        ctrl_layout.addWidget(self.stop_btn)

        layout.addLayout(ctrl_layout)

    
    def filter_table(self, filters):
        print(filters)


    def start_sniffing(self):
        if not self.interface: return

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        
        self.worker = HexParticleWorker(self.interface)
        self.worker.packet_received.connect(self.process_incoming_packet)
        self.worker.start()


    def process_incoming_packet(self, dissected_pack: DissectedPacket):
        if dissected_pack is None or len(dissected_pack._layers) == 0:
            raise RowConstructionError("Layer count must be at least 1")

        self.most_recent_packet = dissected_pack
        self.construct_row(dissected_pack)

    
    def construct_row(self, dp: DissectedPacket):
        net_layer_pack = dp._layers[1]

        if isinstance(net_layer_pack, proto.IPV4Header):
            self.construct_ipv4_row(dp)
        elif isinstance(net_layer_pack, proto.IPV6Header):
            self.construct_ipv6_row(dp)
        elif isinstance(net_layer_pack, proto.ARPHeader):
            self.construct_arp_row(dp)
        
    
    def construct_ipv4_row(self, dp: DissectedPacket):
        if dp.packets_count() < 3:
            raise RowConstructionError("Layer count must be at least 3!")
        
        transport_layer_pack = dp._layers[2]
        if isinstance(transport_layer_pack, proto.ICMPHeader):
            return self.construct_icmp_row(dp)
        elif isinstance(transport_layer_pack, proto.TCPHeader):
            return self.construct_tcp_row(dp)
        elif isinstance(transport_layer_pack, proto.UDPHeader):
            return self.construct_udp_row(dp)

    
    def construct_tcp_row(self, dissected_pack: DissectedPacket):
        iph = dissected_pack._layers[1]
        tcph: proto.TCPHeader = dissected_pack._layers[2]
        
        if isinstance(iph, proto.IPV4Header):
            src_ip = ip_to_str(iph.src)
            dst_ip = ip_to_str(iph.dst)
        else:
            src_ip = ipv6_to_str(iph.src)
            dst_ip = ipv6_to_str(iph.dst)

        self.current_session_key = self.tcp_conns.manage_tcp_packet(iph, tcph)

        src_port = tcph.sport
        dst_port = tcph.dport
        seq = tcph.seq
        ack = tcph.ack
        flags = " | ".join(tcph.flags_str())

        info = f"{src_port} -> {dst_port}{f', [{flags}]' if flags else ''}, Seq={seq}, Ack={ack}"
        self.add_packet_row(src_ip, dst_ip, 'TCP', dissected_pack.length, info, dissected_pack)

    
    def construct_udp_row(self, dissected_pack: DissectedPacket):
        iph = dissected_pack._layers[1]
        udph: proto.TCPHeader = dissected_pack._layers[2]

        if isinstance(iph, proto.IPV4Header):
            src_ip = ip_to_str(iph.src)
            dst_ip = ip_to_str(iph.dst)
        else:
            src_ip = ipv6_to_str(iph.src)
            dst_ip = ipv6_to_str(iph.dst)

        src_port = udph.sport
        dst_port = udph.dport
        length = udph.length

        info = f"{src_port} -> {dst_port}, Len={length}"
        self.add_packet_row(src_ip, dst_ip, 'UDP', dissected_pack.length, info, dissected_pack)

    
    def construct_icmp_row(self, dissected_pack: DissectedPacket):
        iph: proto.IPV4Header = dissected_pack._layers[1]
        icmph: proto.ICMPHeader = dissected_pack._layers[2]

        src_ip = ip_to_str(iph.src)
        dst_ip = ip_to_str(iph.dst)

        type_ = icmph.type
        info = icmp.icmp_type_meaning(type_)

        self.add_packet_row(src_ip, dst_ip, 'ICMP', dissected_pack.length, info, dissected_pack)


    def construct_ipv6_row(self, dissected_pack: DissectedPacket):
        if len(dissected_pack._layers) < 3:
            # raise RowConstructionError("Layer count must be at least 3!")

            # accepts only TCP and UP at the moment
            return

        transport_layer_pack = dissected_pack._layers[2]
        if isinstance(transport_layer_pack, proto.ICMPHeader):
            return self.construct_icmp_row(dissected_pack)
        elif isinstance(transport_layer_pack, proto.TCPHeader):
            return self.construct_tcp_row(dissected_pack)
        elif isinstance(transport_layer_pack, proto.UDPHeader):
            return self.construct_udp_row(dissected_pack)

    
    def construct_arp_row(self, dissected_pack: DissectedPacket):
        arp = dissected_pack._layers[1]
        
        src_mac = mac_to_str(arp.sha)
        dst_mac = mac_to_str(arp.tha)

        src_ip = ip_to_str(arp.spa)
        dst_ip = ip_to_str(arp.tpa)
        
        info = "ARP Packet"
        
        if arp.op == proto.ARP_REQUEST:
            info = f"Who has {dst_ip}? Tell {src_ip} ({src_mac})"
        elif arp.op == proto.ARP_RESPONSE:
            info = f"{src_ip} is at {src_mac}"

        self.add_packet_row(src_mac, dst_mac, "ARP", dissected_pack.length, info, dissected_pack)


    def add_packet_row(self, src: str, dst: str, proto: int, length: int, info: str, dissected_pack: DissectedPacket):
        row = self.packet_table.rowCount()
        self.packet_table.insertRow(row)

        self.packets.append(dissected_pack)

        src_item = QTableWidgetItem(str(src))
        src_item.setData(QtCore.Qt.ItemDataRole.UserRole, len(self.packets) - 1)
        
        self.packet_table.setItem(row, 0, src_item)
        self.packet_table.setItem(row, 1, QTableWidgetItem(str(dst)))

        self.packet_table.setItem(row, 0, QTableWidgetItem(str(src)))
        self.packet_table.setItem(row, 1, QTableWidgetItem(str(dst)))
        self.packet_table.setItem(row, 2, QTableWidgetItem(str(proto)))
        self.packet_table.setItem(row, 3, QTableWidgetItem(str(length)))
        self.packet_table.setItem(row, 4, QTableWidgetItem(str(info)))

        self.packet_table.scrollToBottom()

    
    def on_row_selected(self, item):
        row_index = item.row()
        
        if row_index < len(self.packets):
            self.selected_packet = self.packets[row_index]
            
            self.dissector.display_packet(self.selected_packet)
            self.hex_viewer.set_data(self.selected_packet._raw)


    def stop_sniffing(self):
        if self.worker:
            self.worker.stop()
            self.worker.wait()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    
    def show_row_context_menu(self, position: QtCore.QPoint):
        menu = QMenu()
        packet = self.packet_table.itemAt(position)

        print(repr(position))
        
        if packet:
            action_follow = menu.addAction(f"Follow")
            action = menu.exec(self.packet_table.mapToGlobal(position))
            if action == action_follow:
                print(f"Following a TCP stream...")


class RowConstructionError(ValueError):
    def __init__(self, *args):
        super().__init__(*args)