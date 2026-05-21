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


if __name__ == "__main2__":
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


if __name__ == "__main__":
    from core.netdsl import tokenizer
    from core.netdsl import Parser

    source = "from ip 10.0.0.1 to port"
    tkzer = tokenizer.Tokenizer(source)

    tokens_input = tkzer.tokenize()
    parser = Parser(tokens_input)
    root_stmt = parser.parse_from_stmt()
    
    print("Parsing pass trace complete.")
    print(f"Statement Node Target Type : {root_stmt.type.name}")
    print(f"  ├─ From Expression Class : {type(root_stmt.from_expr).__name__} (Type: {root_stmt.from_expr.type.name})")
    print(f"  │   └─ Value             : {root_stmt.from_expr.value.octets}")
    print(f"  └─ To Expression Class   : {type(root_stmt.to_expr).__name__} (Type: {root_stmt.to_expr.type.name})")
    print(f"      └─ Value             : {root_stmt.to_expr.value}")