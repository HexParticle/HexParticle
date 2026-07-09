# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

from  PyQt6 import QtCore, QtGui, QtWidgets

from hexlib.protocol import icmp, ip, arp, tcp, udp
from hexlib import ParsedPacket

from components import ProtocolDissector, HexViewer, ConfirmationDialog

from features.tcp_inspector import (
    TcpSessionAssemblyWindow,
    TcpStreamContext,
    gen_tcp_stream_key
)

from features.listener.packet_capturer import PacketCapturerThread
from features.listener.packet_processor import PacketProcessorThread
from features import scripting

import hexlib
import app_ctx
import style_loader
import netdsl

import typing

class InterfaceListenerWindow(QtWidgets.QMainWindow):
    def __init__(self, ctx: app_ctx.AppContext):
        super().__init__()

        # reassembling TCP segments
        self.tcp_stream_ctx = TcpStreamContext()
        
        self.capture_thread = None
        
        # processing each packet in a separate thread
        self.packet_process_thread = PacketProcessorThread(self.tcp_stream_ctx)
        
        # processed packets
        self.packets: typing.List[ParsedPacket] = []

        # application context
        self._ctx = ctx

        # the most recent packet
        self.most_recent_packet: ParsedPacket = None

        # the currently selected packet
        self.selected_packet: ParsedPacket = None

        self.tcp_session_windows = [] # keeping references so windows don't close immediately

        self.init_ui()

        # start the packet processing thread
        self.packet_process_thread.on_packet_processed(self.__construct_row)
        self.packet_process_thread.start()


    def init_ui(self):
        self.setWindowTitle("HexParticle Sniffer")
        self.resize(1000, 600)
        self.setStyleSheet(style_loader.get_style("./styles/interface_listener.css"))

        self._create_menu_bar()

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
        
        self.scripting_action = QtGui.QAction(QtGui.QIcon("../assets/script.png"), "Script", self)
        self.scripting_action.triggered.connect(self.start_scripting_window)
        self.toolbar.addAction(self.scripting_action)
        
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


    def _create_menu_bar(self):
        menu_bar = self.menuBar()

        self.file_menu = QtWidgets.QMenu("&File", self)
        menu_bar.addMenu(self.file_menu)

    
    def filter_table(self, filters):
        print(filters)


    def start_sniffing(self):
        if self.packet_table.rowCount() > 0:
            dialog = ConfirmationDialog(
                parent=self,
                message="Do you want to restart the current capture?",
                title="Restart Session"
            )

            if dialog.exec() != ConfirmationDialog.DialogCode.Accepted:
                return

            print("Restarting network engine...")
            self.packet_table.clearContents()
            self.packet_table.setRowCount(0)
            self.packets = []

        self._start_worker()

    
    def _start_worker(self):
        self.start_action.setEnabled(False)
        self.stop_action.setEnabled(True)

        self.capture_thread = PacketCapturerThread(self._ctx._lib)
        self.capture_thread.on_packet_captured(self.__ingest_incoming_packet)
        self.capture_thread.start()


    '''
    Prepares the packet for row construction.
    '''
    def __ingest_incoming_packet(self, pp: ParsedPacket):
        if pp is None: return

        self.packet_process_thread.enqueue(pp)
        
        self.most_recent_packet = pp
        self.packets.append(pp)

    
    def __construct_row(self, pp: ParsedPacket):
        if pp is None or len(pp) == 0:
            raise RowConstructionError("Layer count must be at least 1")

        net_layer_pack = pp._layers[1]

        if isinstance(net_layer_pack, ip.IPV4Header):
            self.construct_ipv4_row(pp)
        elif isinstance(net_layer_pack, ip.IPV6Header):
            self.construct_ipv6_row(pp)
        elif isinstance(net_layer_pack, arp.ARPHeader):
            self.construct_arp_row(pp)
        
    
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
            # accepts only TCP and UDP at the moment
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

        src_item = QtWidgets.QTableWidgetItem(str(src))
        src_item.setData(QtCore.Qt.ItemDataRole.UserRole, len(self.packets) - 1)
        
        self.packet_table.setItem(row, 0, src_item)
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
        if self.capture_thread:
            self.capture_thread.stop()
            self.capture_thread.wait()
        self.start_action.setEnabled(True)
        self.stop_action.setEnabled(False)

    
    def closeEvent(self, event: QtGui.QCloseEvent):
        if len(self.packets) > 0:
            reply = QtWidgets.QMessageBox.question(
                self, 'Confirm Close', 'Are you sure you want to close?',
                QtWidgets.QMessageBox.StandardButton.Yes | QtWidgets.QMessageBox.StandardButton.No
            )

            if reply == QtWidgets.QMessageBox.StandardButton.Yes:
                self._ctx.dispose_library()
                event.accept()
            else:
                event.ignore()
        else:
            self._ctx.dispose_library()
            event.accept()

    
    def start_scripting_window(self):
        self.scripting_window = scripting.ScriptEditorWindow(
            netdsl.parse,
            netdsl.emit_bpf
        )
    
        self.scripting_window.on_filter_change(self.handle_compiled_bpf_output)
        self.scripting_window.show()

    
    def handle_compiled_bpf_output(self, bpf_output):
        if self.capture_thread is None:
            dialog = ConfirmationDialog(
                parent=self, 
                message="Do you want to start the capture?",
                title="Start Session"
            )

            dialog.on_accept(self.start_sniffing)
            dialog.exec()

        if self.capture_thread is not None:
            self.capture_thread.update_filter(bpf_output)

    
    def show_row_context_menu(self, position: QtCore.QPoint):
        item = self.packet_table.itemAt(position)
        if item is None: return

        row_index = item.row()
        parsed_pack = self.packets[row_index]

        if parsed_pack is None: return

        main_menu = QtWidgets.QMenu(self.packet_table)
        follow_menu = QtWidgets.QMenu("Follow", main_menu)

        follow_tcp = follow_menu.addAction("TCP Stream")
        follow_ip = follow_menu.addAction("IP Stream")

        if not parsed_pack.is_tcp_packet():
            follow_tcp.setEnabled(False)

        if not parsed_pack.is_ipv4_packet():
            follow_ip.setEnabled(False)
        
        main_menu.addMenu(follow_menu)
        action = main_menu.exec(QtGui.QCursor.pos())

        if action == follow_tcp and parsed_pack.is_tcp_packet():
            packet = self.packets[row_index]
            
            if packet is None:
                print("Bug: Packet not found at row")
            else:
                self.show_tcp_session_assembly_window(packet)

    
    def show_tcp_session_assembly_window(self, packet: ParsedPacket):
        ip = packet.get_ip_layer()
        tcp = packet.get_tcp_layer()

        stream_key = gen_tcp_stream_key(ip, tcp)
        print("Find stream key: ", stream_key)

        if self.tcp_stream_ctx.is_stream_open(stream_key):
            stream = self.tcp_stream_ctx.get_stream(stream_key)
            stream_window = TcpSessionAssemblyWindow(stream)
            self.tcp_session_windows.append(stream_window)
            stream_window.show()


class RowConstructionError(ValueError):
    def __init__(self, *args):
        super().__init__(*args)