# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QListWidget, QListWidgetItem, QLabel)

from windows import InterfaceListenerWindow
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
        
        layout.addWidget(QLabel("Select an interface to start analysis:"))
        
        self.interface_list = QListWidget()
        layout.addWidget(self.interface_list)

        self.load_interfaces()


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
        if_listener = InterfaceListenerWindow(interface=interface_name, ctx=self._ctx)
        
        self.active_listeners.append(if_listener)
        if_listener.show()