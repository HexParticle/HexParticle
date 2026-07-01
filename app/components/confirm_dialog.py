# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

from PyQt6.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton
from PyQt6.QtCore import Qt

import typing
class ConfirmationDialog(QDialog):
    def __init__(self, parent=None, title="HexParticle", message="A message"):
        super().__init__(parent)

        self.setWindowTitle(title)
        self.setModal(True)
        self.setFixedSize(350, 130)

        layout = QVBoxLayout(self)

        label = QLabel(message)
        label.setWordWrap(True)
        layout.addWidget(label)

        btn_layout = QHBoxLayout()

        cancel_btn = QPushButton("Cancel")
        proceed_btn = QPushButton("Proceed")

        proceed_btn.setDefault(True)

        cancel_btn.clicked.connect(self.reject)
        proceed_btn.clicked.connect(self.accept)

        btn_layout.addStretch()
        btn_layout.addWidget(cancel_btn)
        btn_layout.addWidget(proceed_btn)

        layout.addLayout(btn_layout)