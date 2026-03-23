# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation <https://kagatifoundation.github.org>

from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, 
                                    QTableWidget, QTableWidgetItem, QPushButton, QLabel)
from PyQt6.QtCore import QThread, pyqtSignal

import PyQt6.QtWidgets as pyqtw
from  PyQt6 import QtCore

from hex.lib_wrapper import HexParticle, PacketWrapper
from hex import protocols as protos, ipv6_to_str, ip_to_str, mac_to_str, ip, icmp
from protocol_dissector import ProtocolDissector
from dissectors import HexViewer

import style_loader

class HexParticleWorker(QThread):
    packet_received = pyqtSignal(PacketWrapper)

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
        
        layout.addWidget(QLabel("Live Packets (IPv4 Protocol Mapping):"))
        self.main_splitter = pyqtw.QSplitter(QtCore.Qt.Orientation.Vertical)

        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(5)
        self.packet_table.setHorizontalHeaderLabels(
            ["Source", "Destination", "Protocol", "Length", "Info"]
        )
        self.packet_table.horizontalHeader().setStretchLastSection(True)
        # self.packet_table.setAlternatingRowColors(True)

        self.packet_table.itemClicked.connect(self.on_row_selected)

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


    def process_incoming_packet(self, pwrapper: PacketWrapper):
        if pwrapper is None or len(pwrapper.layers) == 0:
            raise RowConstructionError("Layer count must be at least 1")

        self.construct_row(pwrapper)

    
    def construct_row(self, pw: PacketWrapper):
        net_layer_pack = pw.layers[1]

        if isinstance(net_layer_pack, protos.IPV4Header):
            self.construct_ipv4_row(pw)
        elif isinstance(net_layer_pack, protos.IPV6Header):
            self.construct_ipv6_row(pw)
        elif isinstance(net_layer_pack, protos.ARPHeader):
            self.construct_arp_row(pw)
        
    
    def construct_ipv4_row(self, pw: PacketWrapper):
        if len(pw.layers) < 3:
            raise RowConstructionError("Layer count must be at least 3!")
        
        transport_layer_pack = pw.layers[2]
        if isinstance(transport_layer_pack, protos.ICMPHeader):
            return self.construct_icmp_row(pw)
        elif isinstance(transport_layer_pack, protos.TCPHeader):
            return self.construct_tcp_row(pw)
        elif isinstance(transport_layer_pack, protos.UDPHeader):
            return self.construct_udp_row(pw)

    
    def construct_tcp_row(self, pwrapper: PacketWrapper):
        iph = pwrapper.layers[1]
        tcph: protos.TCPHeader = pwrapper.layers[2]

        if isinstance(iph, protos.IPV4Header):
            src_ip = ip_to_str(iph.src)
            dst_ip = ip_to_str(iph.dst)
        else:
            src_ip = ipv6_to_str(iph.src)
            dst_ip = ipv6_to_str(iph.dst)

        src_port = tcph.sport
        dst_port = tcph.dport
        seq = tcph.seq
        ack = tcph.ack
        flags = " | ".join(tcph.flags_str())

        info = f"{src_port} -> {dst_port}{f', [{flags}]' if flags else ''}, Seq={seq}, Ack={ack}"
        self.add_packet_row(src_ip, dst_ip, 'TCP', pwrapper.length, info, pwrapper)

    
    def construct_udp_row(self, pwrapper: PacketWrapper):
        iph = pwrapper.layers[1]
        udph: protos.TCPHeader = pwrapper.layers[2]

        if isinstance(iph, protos.IPV4Header):
            src_ip = ip_to_str(iph.src)
            dst_ip = ip_to_str(iph.dst)
        else:
            src_ip = ipv6_to_str(iph.src)
            dst_ip = ipv6_to_str(iph.dst)

        src_port = udph.sport
        dst_port = udph.dport
        length = udph.length

        info = f"{src_port} -> {dst_port}, Len={length}"
        self.add_packet_row(src_ip, dst_ip, 'UDP', pwrapper.length, info, pwrapper)

    
    def construct_icmp_row(self, pwrapper: PacketWrapper):
        iph: protos.IPV4Header = pwrapper.layers[1]
        icmph: protos.ICMPHeader = pwrapper.layers[2]

        src_ip = ip_to_str(iph.src)
        dst_ip = ip_to_str(iph.dst)

        type_ = icmph.type
        info = icmp.icmp_type_meaning(type_)

        self.add_packet_row(src_ip, dst_ip, 'ICMP', pwrapper.length, info, pwrapper)


    def construct_ipv6_row(self, pwrapper: PacketWrapper):
        if len(pwrapper.layers) < 3:
            # raise RowConstructionError("Layer count must be at least 3!")

            # accepts only TCP and UP at the moment
            return

        transport_layer_pack = pwrapper.layers[2]
        if isinstance(transport_layer_pack, protos.ICMPHeader):
            return self.construct_icmp_row(pwrapper)
        elif isinstance(transport_layer_pack, protos.TCPHeader):
            return self.construct_tcp_row(pwrapper)
        elif isinstance(transport_layer_pack, protos.UDPHeader):
            return self.construct_udp_row(pwrapper)

    
    def construct_arp_row(self, pwrapper: PacketWrapper):
        arp = pwrapper.layers[1]
        
        src_mac = mac_to_str(arp.sha)
        dst_mac = mac_to_str(arp.tha)

        src_ip = ip_to_str(arp.spa)
        dst_ip = ip_to_str(arp.tpa)
        
        info = "ARP Packet"
        
        if arp.op == protos.ARP_REQUEST:
            info = f"Who has {dst_ip}? Tell {src_ip} ({src_mac})"
        elif arp.op == protos.ARP_RESPONSE:
            info = f"{src_ip} is at {src_mac}"

        self.add_packet_row(src_mac, dst_mac, "ARP", pwrapper.length, info, pwrapper)


    def add_packet_row(self, src, dst, proto, length, info, pwrapper):
        row = self.packet_table.rowCount()
        self.packet_table.insertRow(row)

        self.packets.append(pwrapper)

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
            selected_packet = self.packets[row_index]
            
            self.dissector.display_packet(selected_packet)
            self.hex_viewer.set_data(selected_packet.raw)


    def stop_sniffing(self):
        if self.worker:
            self.worker.stop()
            self.worker.wait()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)


class RowConstructionError(ValueError):
    def __init__(self, *args):
        super().__init__(*args)