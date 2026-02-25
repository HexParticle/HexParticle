# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation <https://kagatifoundation.github.org>

from interface_picker_widget import InterfacePicker
from PyQt6.QtWidgets import QApplication
import sys

if __name__ == "__main__":
	def run_app():
		app = QApplication(sys.argv)
		interface_picker = InterfacePicker()

		interface_picker.show()
		sys.exit(app.exec())
	
	run_app()