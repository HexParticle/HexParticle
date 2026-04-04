# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

from  PyQt6 import QtCore, QtGui, QtWidgets

from hexlib.protocol import icmp, ip, arp, tcp, udp
from hexlib.lib_wrapper import HexParticle
from hexlib import ParsedPacket
from components import ProtocolDissector, HexViewer

import hexlib
import app_ctx
import tcp_conn_ctx as tcpcon
import style_loader

class HexParticleWorker(QtCore.QThread):
    packet_received = QtCore.pyqtSignal(ParsedPacket)

    def __init__(self, interface: str, lib_path: str):
        super().__init__()
        self.interface = interface
        self.running = True
        self.hexp = HexParticle(interface, lib_path)


    def run(self):
        try:
            while self.running:
                packet = self.hexp.next_packet()
                if packet:
                    self.packet_received.emit(packet)
            self.hexp.close()
        except Exception as e:
            print(e)


    def stop(self):
        self.running = False


class InterfaceListenerWindow(QtWidgets.QMainWindow):
    def __init__(self, interface: str, ctx: app_ctx.AppContext):
        super().__init__()
        self.worker = None
        self.interface = interface
        self.packets = []
        self._ctx = ctx

        # the most recent packet
        self.most_recent_packet: ParsedPacket = None

        # the currently selected packet
        self.selected_packet: ParsedPacket = None

        # reassembling TCP segments
        self.tcp_conns: tcpcon.TCPConnectionCtx = tcpcon.TCPConnectionCtx()

        self.tcp_session_windows = [] # keeping references so windows don't close immediately

        self.init_ui()


    def init_ui(self):
        self.setWindowTitle("HexParticle Sniffer")
        self.resize(1000, 600)
        self.setStyleSheet(style_loader.get_style("./styles/interface_listener.css"))

        self.toolbar = QtWidgets.QToolBar("Main Toolbar")
        self.addToolBar(self.toolbar)

        self.start_action = QtGui.QAction(QtGui.QIcon("../assets/play.png"), "Start", self)
        self.start_action.triggered.connect(self.start_sniffing)
        self.toolbar.addAction(self.start_action)

        self.stop_action = QtGui.QAction(QtGui.QIcon("../assets/stop.png"), "Stop", self)
        self.stop_action.triggered.connect(self.stop_sniffing)
        self.stop_action.setEnabled(False)
        self.toolbar.addAction(self.stop_action)

        container = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(container)
        
        self.search_bar = QtWidgets.QLineEdit()
        self.search_bar.setPlaceholderText("Filter by Protocol or IP (e.g., TCP, 192.168...)")
        self.search_bar.textChanged.connect(self.filter_table)
        layout.addWidget(self.search_bar)
        
        self.main_splitter = QtWidgets.QSplitter(QtCore.Qt.Orientation.Vertical)

        self.packet_table = QtWidgets.QTableWidget()
        self.packet_table.setColumnCount(5)
        self.packet_table.setHorizontalHeaderLabels(
            ["Source", "Destination", "Protocol", "Length", "Info"]
        )
        self.packet_table.horizontalHeader().setStretchLastSection(True)

        self.packet_table.itemClicked.connect(self.on_row_selected)
        self.packet_table.setContextMenuPolicy(QtCore.Qt.ContextMenuPolicy.CustomContextMenu)
        self.packet_table.customContextMenuRequested.connect(self.show_row_context_menu)

        self.main_splitter.addWidget(self.packet_table)

        self.dissector = ProtocolDissector()
        self.hex_viewer = HexViewer()
        
        self.bottom_splitter = QtWidgets.QSplitter(QtCore.Qt.Orientation.Horizontal)
        self.bottom_splitter.addWidget(self.dissector)
        self.bottom_splitter.addWidget(self.hex_viewer)
        
        self.main_splitter.addWidget(self.bottom_splitter)

        self.bottom_splitter.setStretchFactor(0, 1)
        self.bottom_splitter.setStretchFactor(1, 1)

        layout.addWidget(self.main_splitter)
        self.setCentralWidget(container)

    
    def filter_table(self, filters):
        print(filters)


    def start_sniffing(self):
        if not self.interface: return

        self.start_action.setEnabled(False)
        self.stop_action.setEnabled(True)
        
        lib_path = self._ctx.cmdline_options.lib_path
        self.worker = HexParticleWorker(self.interface, lib_path)

        self.worker.packet_received.connect(self.process_incoming_packet)
        self.worker.start()


    def process_incoming_packet(self, dissected_pack: ParsedPacket):
        if dissected_pack is None or len(dissected_pack._layers) == 0:
            raise RowConstructionError("Layer count must be at least 1")

        self.most_recent_packet = dissected_pack
        self.construct_row(dissected_pack)

    
    def construct_row(self, dp: ParsedPacket):
        net_layer_pack = dp._layers[1]

        if isinstance(net_layer_pack, ip.IPV4Header):
            self.construct_ipv4_row(dp)
        elif isinstance(net_layer_pack, ip.IPV6Header):
            self.construct_ipv6_row(dp)
        elif isinstance(net_layer_pack, arp.ARPHeader):
            self.construct_arp_row(dp)
        
    
    def construct_ipv4_row(self, dp: ParsedPacket):
        if dp.packets_count() < 3:
            raise RowConstructionError("Layer count must be at least 3!")
        
        transport_layer_pack = dp._layers[2]
        if isinstance(transport_layer_pack, icmp.ICMPHeader):
            return self.construct_icmp_row(dp)
        elif isinstance(transport_layer_pack, tcp.TCPHeader):
            return self.construct_tcp_row(dp)
        elif isinstance(transport_layer_pack, udp.UDPHeader):
            return self.construct_udp_row(dp)

    
    def construct_tcp_row(self, dissected_pack: ParsedPacket):
        iph = dissected_pack._layers[1]
        tcph: tcp.TCPHeader = dissected_pack._layers[2]
        
        if isinstance(iph, ip.IPV4Header):
            src_ip = hexlib.ip_to_str(iph.src)
            dst_ip = hexlib.ip_to_str(iph.dst)
        else:
            src_ip = hexlib.ipv6_to_str(iph.src)
            dst_ip = hexlib.ipv6_to_str(iph.dst)

        self.current_session_key = self.tcp_conns.manage_tcp_packet(iph, tcph)

        src_port = tcph.sport
        dst_port = tcph.dport
        seq = tcph.seq
        ack = tcph.ack
        flags = " | ".join(tcph.flags_str())

        info = f"{src_port} -> {dst_port}{f', [{flags}]' if flags else ''}, Seq={seq}, Ack={ack}"
        self.add_packet_row(src_ip, dst_ip, 'TCP', dissected_pack.length, info, dissected_pack)

    
    def construct_udp_row(self, dissected_pack: ParsedPacket):
        iph = dissected_pack._layers[1]
        udph: tcp.TCPHeader = dissected_pack._layers[2]

        if isinstance(iph, ip.IPV4Header):
            src_ip = hexlib.ip_to_str(iph.src)
            dst_ip = hexlib.ip_to_str(iph.dst)
        else:
            src_ip = hexlib.ipv6_to_str(iph.src)
            dst_ip = hexlib.ipv6_to_str(iph.dst)

        src_port = udph.sport
        dst_port = udph.dport
        length = udph.length

        info = f"{src_port} -> {dst_port}, Len={length}"
        self.add_packet_row(src_ip, dst_ip, 'UDP', dissected_pack.length, info, dissected_pack)

    
    def construct_icmp_row(self, dissected_pack: ParsedPacket):
        iph: ip.IPV4Header = dissected_pack._layers[1]
        icmph: icmp.ICMPHeader = dissected_pack._layers[2]

        src_ip = hexlib.ip_to_str(iph.src)
        dst_ip = hexlib.ip_to_str(iph.dst)

        type_ = icmph.type
        info = icmp.icmp_type_meaning(type_)

        self.add_packet_row(src_ip, dst_ip, 'ICMP', dissected_pack.length, info, dissected_pack)


    def construct_ipv6_row(self, dissected_pack: ParsedPacket):
        if len(dissected_pack._layers) < 3:
            # raise RowConstructionError("Layer count must be at least 3!")

            # accepts only TCP and UP at the moment
            return

        transport_layer_pack = dissected_pack._layers[2]
        if isinstance(transport_layer_pack, icmp.ICMPHeader):
            return self.construct_icmp_row(dissected_pack)
        elif isinstance(transport_layer_pack, tcp.TCPHeader):
            return self.construct_tcp_row(dissected_pack)
        elif isinstance(transport_layer_pack, udp.UDPHeader):
            return self.construct_udp_row(dissected_pack)

    
    def construct_arp_row(self, dissected_pack: ParsedPacket):
        arp_layer = dissected_pack._layers[1]
        
        src_mac = hexlib.mac_to_str(arp_layer.sha)
        dst_mac = hexlib.mac_to_str(arp_layer.tha)

        src_ip = hexlib.ip_to_str(arp_layer.spa)
        dst_ip = hexlib.ip_to_str(arp_layer.tpa)
        
        info = "ARP Packet"
        
        if arp_layer.op == arp.ARP_REQUEST:
            info = f"Who has {dst_ip}? Tell {src_ip} ({src_mac})"
        elif arp_layer.op == arp.ARP_RESPONSE:
            info = f"{src_ip} is at {src_mac}"

        self.add_packet_row(src_mac, dst_mac, "ARP", dissected_pack.length, info, dissected_pack)


    def add_packet_row(self, src: str, dst: str, proto: int, length: int, info: str, dissected_pack: ParsedPacket):
        row = self.packet_table.rowCount()
        self.packet_table.insertRow(row)

        self.packets.append(dissected_pack)

        src_item = QtWidgets.QTableWidgetItem(str(src))
        src_item.setData(QtCore.Qt.ItemDataRole.UserRole, len(self.packets) - 1)
        
        self.packet_table.setItem(row, 0, src_item)
        self.packet_table.setItem(row, 1, QtWidgets.QTableWidgetItem(str(dst)))
        self.packet_table.setItem(row, 0, QtWidgets.QTableWidgetItem(str(src)))
        self.packet_table.setItem(row, 1, QtWidgets.QTableWidgetItem(str(dst)))
        self.packet_table.setItem(row, 2, QtWidgets.QTableWidgetItem(str(proto)))
        self.packet_table.setItem(row, 3, QtWidgets.QTableWidgetItem(str(length)))
        self.packet_table.setItem(row, 4, QtWidgets.QTableWidgetItem(str(info)))

    
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
        self.start_action.setEnabled(True)
        self.stop_action.setEnabled(False)

    
    def show_row_context_menu(self, position: QtCore.QPoint):
        menu = QtWidgets.QMenu()
        packet = self.packet_table.itemAt(position)

        if packet:
            action_follow = menu.addAction(f"Follow")
            action = menu.exec(self.packet_table.mapToGlobal(position))
            if action == action_follow:
                print(f"Following a TCP stream...")


class RowConstructionError(ValueError):
    def __init__(self, *args):
        super().__init__(*args)