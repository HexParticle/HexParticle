# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

from PyQt6.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton
from PyQt6.QtCore import Qt

import typing

class ConfirmationDialog(QDialog):
    def __init__(self, parent=None, title: str = "HexParticle", message: str = "A message from HexParticle"):
        super().__init__(parent)
        
        self.setWindowTitle(title)
        self.setModal(True)
        self.setFixedSize(350, 130)
        
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 15)
        layout.setSpacing(15)

        self.label = QLabel(message)
        self.label.setWordWrap(True)
        layout.addWidget(self.label)

        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(10)
        
        self.cancel_btn = QPushButton("Cancel")
        self.proceed_btn = QPushButton("Proceed")
        
        self.cancel_btn.setDefault(True) 
        self.cancel_btn.setStyleSheet("background-color: gray")

        self.proceed_btn.clicked.connect(self.__exec_on_accept)
        self.cancel_btn.clicked.connect(self.__exec_on_reject)

        btn_layout.addStretch() 
        btn_layout.addWidget(self.cancel_btn)
        btn_layout.addWidget(self.proceed_btn)

        layout.addLayout(btn_layout)

        self.on_accept_cb = None
        self.on_reject_cb = None

    
    def on_accept(self, cb: typing.Callable[[], None]):
        self.on_accept_cb = cb

    
    def __exec_on_accept(self):
        if self.on_accept_cb is not None:
            self.on_accept_cb()


    def on_reject(self, cb: typing.Callable[[], None]):
        self.on_reject_cb = cb

	
    def __exec_on_reject(self):
        if self.on_reject_cb is not None:
            self.on_reject_cb()