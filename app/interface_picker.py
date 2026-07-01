# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

from PyQt6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QListWidget,
    QListWidgetItem,
    QLabel,
    QPushButton,
    QFileDialog
)

from PyQt6.QtCore import (
    Qt
)

from PyQt6.QtGui import (
    QIcon
)

from interface_listener import InterfaceListenerWindow
from hexlib.lib_wrapper import HEX_OFFLINE_MODE, HEX_LIVE_MODE

import app_ctx
import style_loader

class InterfacePickerWindow(QWidget):
    def __init__(self, ctx: app_ctx.AppContext):
        super().__init__()
        self._ctx = ctx
        self.active_listeners = []
        self.init_ui()


    def init_ui(self):
        self.setWindowTitle("HexParticle Sniffer")
        self.resize(400, 300) 
        
        self.setStyleSheet(style_loader.get_style("./styles/interface_picker_widget.css"))

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(10)

        header = QLabel("Welcome to HexParticle")
        header.setObjectName("Header")
        layout.addWidget(header)

        self.open_pcap_file_button = QPushButton("Open PCAP File")
        self.open_pcap_file_button.setIcon(QIcon("../assets/open.png"))
        self.open_pcap_file_button.clicked.connect(self.open_pcap_file_picker)
        self.open_pcap_file_button.setCursor(Qt.CursorShape.PointingHandCursor)

        layout.addWidget(self.open_pcap_file_button)

        layout.addWidget(QLabel("Select an interface to start analysis:"))
        
        self.interface_list = QListWidget()
        layout.addWidget(self.interface_list)

        self.load_interfaces()


    def open_pcap_file_picker(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Open Pcap File",
            "",
            "PCAP Files (*.pcap *.pcapng)"
        )

        if file_path:
            self._ctx.initialize_library(file_path, HEX_OFFLINE_MODE)
            if_listener = InterfaceListenerWindow(ctx=self._ctx)
        
            self.active_listeners.append(if_listener)
            if_listener.show()


    def load_interfaces(self):
        try:
            if_names = self._ctx._lib.get_all_interfaces()
            self.interface_list.addItems(if_names)
            self.interface_list.itemDoubleClicked.connect(self.handle_interface_selection)
        except Exception as e:
            self.interface_list.addItem(f"Error: {e}")


    def handle_interface_selection(self, item: QListWidgetItem):
        if not item: return

        if not hasattr(self, 'active_listeners'):
            self.active_listeners = []

        interface_name = item.text()

        self._ctx.initialize_library(interface_name, HEX_LIVE_MODE)

        if_listener = InterfaceListenerWindow(ctx=self._ctx)
        
        self.active_listeners.append(if_listener)
        if_listener.show()