# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

import PyQt6.QtWidgets as widgets

class HexViewer(widgets.QTextEdit):
    def __init__(self):
        super().__init__()
        self.setReadOnly(True)
        self.setFontFamily("Courier New")
        self.setFontPointSize(10)
        self.setStyleSheet("background-color: #1e1e1e; color: #d4d4d4;")

    def set_data(self, raw_bytes: bytes):
        if not raw_bytes:
            self.setText("No payload data.")
            return

        hex_dump = []
        for i in range(0, len(raw_bytes), 16):
            chunk = raw_bytes[i:i+16]
            
            # Address column (0000, 0010, etc)
            address = f"{i:04x}  "
            
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            hex_part = hex_part.ljust(48)
            
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            hex_dump.append(f"{address}{hex_part}  |{ascii_part}|")

        self.setPlainText("\n".join(hex_dump))