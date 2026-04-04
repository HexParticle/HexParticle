# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

from PyQt6.QtWidgets import QApplication

import sys
import signal
import argparse

from app_ctx import AppContext
from windows import InterfacePickerWindow

class HexParticleApplication:
    def __init__(self, ctx: AppContext):
        self._ctx = ctx

    def start(self):
        self._pyqt_app = QApplication(sys.argv)
        interface_picker = InterfacePickerWindow(self._ctx)
        interface_picker.show()
        sys.exit(self._pyqt_app.exec())


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    cmdline_parser = argparse.ArgumentParser(
        prog="HexParticle",
        description="A mini packet analyzer"
    )

    cmdline_parser.add_argument(
        "-l",
        "--lib-path",
        help="libhexp's path"
    )

    app = HexParticleApplication(AppContext(cmdline_parser.parse_args()))
    app.start()