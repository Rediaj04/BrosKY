from PyQt6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                            QTextEdit, QPushButton, QLabel, QFileDialog,
                            QMessageBox, QComboBox)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QSyntaxHighlighter, QTextCharFormat, QColor
import sys
import os
from ...core.executor import GameExecutor

class ScriptHighlighter(QSyntaxHighlighter):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.highlighting_rules = []
        
        # Palabras clave de Lua
        keyword_format = QTextCharFormat()
        keyword_format.setForeground(QColor("#569CD6"))
        keywords = [
            "and", "break", "do", "else", "elseif", "end", "false", "for",
            "function", "if", "in", "local", "nil", "not", "or", "repeat",
            "return", "then", "true", "until", "while"
        ]
        for word in keywords:
            self.highlighting_rules.append((r'\b' + word + r'\b', keyword_format))
            
        # Strings
        string_format = QTextCharFormat()
        string_format.setForeground(QColor("#CE9178"))
        self.highlighting_rules.append((r'"[^"\\]*(\\.[^"\\]*)*"', string_format))
        self.highlighting_rules.append((r"'[^'\\]*(\\.[^'\\]*)*'", string_format))
        
        # Comentarios
        comment_format = QTextCharFormat()
        comment_format.setForeground(QColor("#6A9955"))
        self.highlighting_rules.append((r'--[^\n]*', comment_format))
        
    def highlightBlock(self, text):
        for pattern, format in self.highlighting_rules:
            for match in pattern.finditer(text):
                start, end = match.span()
                self.setFormat(start, end - start, format)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.executor = GameExecutor()
        self.init_ui()
        
    def init_ui(self):
        self.setWindowTitle("RobloxFake Script Executor")
        self.setGeometry(100, 100, 800, 600)
        
        # Widget central
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Layout principal
        layout = QVBoxLayout(central_widget)
        
        # Editor de scripts
        self.script_editor = QTextEdit()
        self.script_editor.setFont(QFont("Consolas", 10))
        self.highlighter = ScriptHighlighter(self.script_editor.document())
        layout.addWidget(self.script_editor)
        
        # Controles
        controls_layout = QHBoxLayout()
        
        # Botón de ejecutar
        self.execute_button = QPushButton("Ejecutar Script")
        self.execute_button.clicked.connect(self.execute_script)
        controls_layout.addWidget(self.execute_button)
        
        # Botón de guardar
        self.save_button = QPushButton("Guardar Script")
        self.save_button.clicked.connect(self.save_script)
        controls_layout.addWidget(self.save_button)
        
        # Botón de cargar
        self.load_button = QPushButton("Cargar Script")
        self.load_button.clicked.connect(self.load_script)
        controls_layout.addWidget(self.load_button)
        
        layout.addLayout(controls_layout)
        
        # Estado
        self.status_label = QLabel("Estado: Desconectado")
        layout.addWidget(self.status_label)
        
        # Conectar al juego
        self.connect_button = QPushButton("Conectar al Juego")
        self.connect_button.clicked.connect(self.connect_to_game)
        layout.addWidget(self.connect_button)
        
    def execute_script(self):
        script = self.script_editor.toPlainText()
        if script:
            if self.executor.execute_script(script):
                QMessageBox.information(self, "Éxito", "Script ejecutado correctamente")
            else:
                QMessageBox.warning(self, "Error", "Error al ejecutar el script")
        else:
            QMessageBox.warning(self, "Error", "El script está vacío")
            
    def save_script(self):
        file_name, _ = QFileDialog.getSaveFileName(
            self,
            "Guardar Script",
            "",
            "Lua Files (*.lua);;All Files (*)"
        )
        if file_name:
            script = self.script_editor.toPlainText()
            with open(file_name, "w") as f:
                f.write(script)
            QMessageBox.information(self, "Éxito", "Script guardado correctamente")
            
    def load_script(self):
        file_name, _ = QFileDialog.getOpenFileName(
            self,
            "Cargar Script",
            "",
            "Lua Files (*.lua);;All Files (*)"
        )
        if file_name:
            with open(file_name, "r") as f:
                script = f.read()
            self.script_editor.setPlainText(script)
            
    def connect_to_game(self):
        if self.executor.attach_to_game():
            self.status_label.setText("Estado: Conectado")
            self.connect_button.setEnabled(False)
            QMessageBox.information(self, "Éxito", "Conectado al juego correctamente")
        else:
            QMessageBox.warning(self, "Error", "No se pudo conectar al juego") 