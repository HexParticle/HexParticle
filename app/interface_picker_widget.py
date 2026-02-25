# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation <https://kagatifoundation.github.org>

from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QListWidget, QListWidgetItem, QLabel)
from hex.lib_wrapper import InterfaceManager
from interface_listener import InterfaceListener
import style_loader

class InterfacePicker(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.active_listeners = []


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
        
        layout.addWidget(QLabel("Select an interface to start analysis:"))
        
        self.interface_list = QListWidget()
        layout.addWidget(self.interface_list)

        self.load_interfaces()


    def load_interfaces(self):
        try:
            manager = InterfaceManager()
            if_names = manager.get_all_interface_names()
            
            self.interface_list.addItems(if_names)
            self.interface_list.itemDoubleClicked.connect(self.handle_interface_selection)

        except Exception as e:
            self.interface_list.addItem(f"Error: {e}")


    def handle_interface_selection(self, item: QListWidgetItem):
        if not item: return

        if not hasattr(self, 'active_listeners'):
            self.active_listeners = []

        interface_name = item.text()
        if_listener = InterfaceListener(interface=interface_name)
        
        self.active_listeners.append(if_listener)
        if_listener.show()