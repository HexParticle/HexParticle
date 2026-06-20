from PyQt6 import QtWidgets as widgets, QtGui, QtCore

class ScriptEditor(widgets.QTextEdit):
    def __init__(self):
        super().__init__()
        self.setReadOnly(False)
        self.setFont(QtGui.QFont("Courier New", 12))
        self.setPlaceholderText(
            "FROM 10.0.0.1 TO 10.0.0.2\n"
            "WHERE\n"
            "    TCP.SRC_PORT = 80,\n"
            "    TCP.SEQ_NUM > 0,\n"
            "    TCP.CKSUM = 5000"
        )


class ScriptEditorWindow(widgets.QWidget):
    def __init__(self, parse_callback=None, emit_callback=None):
        super().__init__()
        self.parse_callback = parse_callback
        self.emit_callback = emit_callback
        
        self.setWindowTitle("NetDSL Scripting Window")
        self.resize(700, 600)
        self.init_ui()
        

    def init_ui(self):
        main_layout = widgets.QVBoxLayout()
        
        self.script_editor = ScriptEditor()
        main_layout.addWidget(widgets.QLabel("Query: "))
        main_layout.addWidget(self.script_editor, stretch=3)

        self.compile_btn = widgets.QPushButton("Compile to BPF")
        self.compile_btn.clicked.connect(self.handle_compile)
        main_layout.addWidget(self.compile_btn)

        self.output_viewer = widgets.QTextEdit()
        self.output_viewer.setReadOnly(True)
        self.output_viewer.setFont(QtGui.QFont("Courier New", 11))
        self.output_viewer.setStyleSheet("background-color: #1e1e1e; color: #a9b7c6;")
        
        main_layout.addWidget(widgets.QLabel("BPF Filter: "))
        main_layout.addWidget(self.output_viewer, stretch=1)

        self.setLayout(main_layout)


    def handle_compile(self):
        dsl_text = self.script_editor.toPlainText().strip()
        if not dsl_text:
            self.output_viewer.setText("Error: Input query is empty.")
            return

        try:
            if self.parse_callback and self.emit_callback:
                ast_root = self.parse_callback(dsl_text)
                if ast_root:
                    bpf_output = self.emit_callback(ast_root)
                    self.output_viewer.setText(f'"{bpf_output}"')
            else:
                self.output_viewer.setText(f"Error")
        except Exception as e:
            self.output_viewer.setText(f"Compilation Error:\n{str(e)}")