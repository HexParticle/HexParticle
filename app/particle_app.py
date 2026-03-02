# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation <https://kagatifoundation.github.org>

from interface_picker_widget import InterfacePicker
from PyQt6.QtWidgets import QApplication

import sys
import signal

def sigint_handler(*args):
    """Handler for the SIGINT signal."""
    print("Quit...")
    QApplication.quit()

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    def run_app():
        app = QApplication(sys.argv)
        interface_picker = InterfacePicker()

        interface_picker.show()
        sys.exit(app.exec())
    
    run_app()