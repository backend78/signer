import os
import subprocess
import random
from shutil import which
import string
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QHBoxLayout, QFileDialog,
    QRadioButton, QMessageBox, QDialog ,QCheckBox,QTextEdit
)
from PyQt5.QtGui import QPixmap, QIcon
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes 
from PyQt5.QtCore import Qt, QTimer, QObject, pyqtSignal, QTextCursor
import threading
import signal

class Worker(QObject):
    output_signal = pyqtSignal(str)

    def __init__(self, process):
        super().__init__()
        self.process = process

    def read_output(self):
        while self.process.poll() is None:
            output = self.process.stdout.readline().decode()
            self.output_signal.emit(output)
        output = self.process.stdout.read().decode()
        self.output_signal.emit(output)

class Window(QWidget): 
    def __init__(self): 
        super().__init__() 
        self.setWindowTitle("Terminal") 
        self.setStyleSheet("background: black;")
        self.setWindowIcon(QIcon("path_to_icon"))  # Replace with your icon path
        self.setGeometry(1315, 310, 550, 400) 
        self.initUI()

        # Timer for changing border color
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.change_border_color)
        self.timer.start(500)  # Change color every 500 milliseconds

    def initUI(self):
        self.layout = QVBoxLayout(self)
        self.output_text = QTextEdit(self)
        self.output_text.setReadOnly(False)
        self.output_text.setFocus()
        self.output_text.setStyleSheet("background-color: black; color: white; font-size: 15px; padding: 10px;border-radius: 25px;")
        self.layout.addWidget(self.output_text)

        self.process = None

        self.output_text.installEventFilter(self)
        self.setLayout(self.layout)

    def execute_command(self):
        cursor = self.output_text.textCursor()
        cursor.select(QTextCursor.LineUnderCursor)
        command = cursor.selectedText().strip()
        self.output_text.append(f">> {command}")

        if command.startswith("cd"):
            path = command.split("cd", 1)[1].strip()
            try:
                os.chdir(path)
                kk = '>'
                self.output_text.append(f"Changed directory to: {os.getcwd()}{kk}")
            except FileNotFoundError:
                self.output_text.append(f"Directory not found: {path}")
            return

        if command.startswith("mkdir"):
            path = command.split("mkdir", 1)[1].strip()
            try:
                os.makedirs(path, exist_ok=True)
                self.output_text.append(f"Directory created: {path}")
            except Exception as e:
                self.output_text.append(f"Error creating directory: {e}")
            return

        if command.startswith("pip install"):
            command = f"python3 -m {command}"

        self.process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        self.worker = Worker(self.process)
        self.worker.output_signal.connect(self.append_output)

        self.output_thread = threading.Thread(target=self.worker.read_output, daemon=True)
        self.output_thread.start()

        self.output_text.append("")

    def append_output(self, output):
        self.output_text.insertPlainText(output)
        self.output_text.moveCursor(QTextCursor.End)

    def eventFilter(self, source, event):
        if event.type() == event.KeyPress and source is self.output_text:
            if event.key() == Qt.Key_Return or event.key() == Qt.Key_Enter:
                self.execute_command()
                return True
            elif event.key() == Qt.Key_C and event.modifiers() & Qt.ControlModifier:
                self.stop_process()
                return True
        return super().eventFilter(source, event)

    def stop_process(self):
        if self.process:
            os.kill(self.process.pid, signal.SIGTERM)

    def change_border_color(self):
        color = QColor(random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))
        self.setStyleSheet(f"background: black; border: 3px solid {color.name()};")


class LicenseWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🔐 License Agreement 🔐")
        self.setFixedSize(593, 394)
        self.setStyleSheet("background-color: RGB(105, 105, 105);")

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        vbox = QVBoxLayout(central_widget)

        bold_font = central_widget.font()
        bold_font.setBold(True)

        image_label = QLabel()
        pixmap = QPixmap("path_to_image")  # Replace with your image path
        pixmap = pixmap.scaledToWidth(200)  # Change image width
        image_label.setPixmap(pixmap)

        self.license_text = QLineEdit()
        self.license_text.setPlaceholderText("Enter License Key")
        self.license_text.setStyleSheet("border-radius: 10px; background-color: white; color: black; padding: 5px; width: 400px;")

        submit_button = QPushButton('Submit')
        submit_button.clicked.connect(self.on_submit)
        submit_button.setStyleSheet("QPushButton { border-radius: 15px; background-color: rgb(46, 204, 113); color: white; padding: 10px; width:100px; }" "QPushButton:hover {background-color: #3CB371;}")

        channel_label = QLabel('Website:')
        channel_link = QLabel('<a href="https://blue-elite.tech/">https://blue-elite.tech/</a>')
        channel_link.setOpenExternalLinks(True)

        hbox_channel = QHBoxLayout()
        hbox_channel.addWidget(channel_label)
        hbox_channel.addWidget(channel_link)
        hbox_channel.setAlignment(Qt.AlignLeft)

        vbox.addWidget(image_label, alignment=Qt.AlignCenter)
        vbox.addWidget(self.license_text, alignment=Qt.AlignCenter)
        vbox.addWidget(submit_button, alignment=Qt.AlignCenter)
        vbox.addLayout(hbox_channel)

        self.set_icon()
        
    def on_submit(self):
        license_key = self.license_text.text()
        if (license_key == '1'):
            self.close()  
            self.show_app_protector()
        else:
            QMessageBox.warning(self, '❗️ Invalid license key!', 'Please try again or contact | @Z_3u5❗️')

    def show_app_protector(self):
        self.app_protector = AppProtector()
        self.app_protector.show()

    def set_icon(self):
        icon_path = os.path.abspath(os.path.join(os.getcwd(), 'ic', 'logoo.ico'))
        self.setWindowIcon(QIcon(icon_path))

class MultiChoiceDialog(QDialog):
    def __init__(self, options, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Select Options")
        layout = QVBoxLayout(self)
        self.checkboxes = []
        for option in options:
            checkbox = QCheckBox(option)
            layout.addWidget(checkbox)
            self.checkboxes.append(checkbox)

        # Add Ok and Cancel buttons
        button_layout = QHBoxLayout()
        ok_button = QPushButton("OK")
        ok_button.clicked.connect(self.accept)
        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(ok_button)
        button_layout.addWidget(cancel_button)
        layout.addLayout(button_layout)

        # Set dialog size
        self.adjustSize()

class AppProtector(QWidget):
    output_signal = pyqtSignal(str)  # إشارة جديدة لإرسال المخرجات

    def __init__(self):
        super().__init__()
        self.setWindowTitle('APK Obfuscator|GhostHackerNetwork v1.0™')
        self.setFixedSize(700, 400)
        self.setStyleSheet("background-color: RGB(105, 105, 105);")

        vbox = QVBoxLayout(self)
        bold_font = self.font()
        bold_font.setBold(True)

        # زر إظهار المحطة الطرفية
        show_log_btn = QPushButton('Show Log⬛')
        show_log_btn.setStyleSheet(
            "QPushButton {background-color: #777777; color: white; border-radius: 15px; padding: 10px 20px; min-width: 50px;}"
            "QPushButton:hover {background-color: #da0481;}"
        )
        show_log_btn.clicked.connect(self.show_terminal)
        vbox.addWidget(show_log_btn, alignment=Qt.AlignRight)

        apk_label = QLabel('Select APK file ')
        apk_label.setFont(bold_font)
        apk_label.setStyleSheet("color: rgb(255, 255, 255); font-size: 25px; color: black;  font-family:Times New Roman;")
        apk_label.setAlignment(Qt.AlignCenter)

        self.apk_text = QLineEdit()
        self.apk_text.setReadOnly(True)
        self.apk_text.setStyleSheet("border-radius: 10px; background-color: white; color: black; padding: 5px; width: 400px;")

        apk_browse_btn = QPushButton('Browse')
        apk_browse_btn.setStyleSheet("QPushButton {background-color: #3498db;color: white; border-radius: 15px; padding: 10px 20px; min-width: 50px;}" "QPushButton:hover {background-color: #da1181;}")
        apk_browse_btn.clicked.connect(self.on_browse)

        operation_label = QLabel('Select operation 👇')
        operation_label.setFont(bold_font)
        operation_label.setStyleSheet("color: rgb(255, 255, 255); font-size: 25px; color: black;  font-family:Times New Roman;")
        operation_label.setAlignment(Qt.AlignCenter)

        # Initialize radio buttons for selecting operation
        self.encrypt_radio = QRadioButton('encryption')
        self.encrypt_radio.setChecked(False)
        self.encrypt_radio.toggled.connect(self.on_radio_change)

        self.decrypt_radio = QRadioButton('decryption')
        self.decrypt_radio.setChecked(False)
        self.decrypt_radio.toggled.connect(self.on_radio_change)

        self.delete_radio = QRadioButton('delete')
        self.delete_radio.setChecked(False)
        self.delete_radio.toggled.connect(self.on_radio_change)

        vbox.addWidget(apk_label, alignment=Qt.AlignCenter)
        hbox = QHBoxLayout()
        hbox.addWidget(self.apk_text, alignment=Qt.AlignCenter)
        hbox.addWidget(apk_browse_btn, alignment=Qt.AlignCenter)
        vbox.addLayout(hbox)

        vbox.addWidget(operation_label, alignment=Qt.AlignCenter)
        vbox.addWidget(self.encrypt_radio, alignment=Qt.AlignCenter)
        vbox.addWidget(self.decrypt_radio, alignment=Qt.AlignCenter)
        vbox.addWidget(self.delete_radio, alignment=Qt.AlignCenter)

        protect_btn = QPushButton('Protect 🛡️')
        protect_btn.setStyleSheet(
            "QPushButton {background-color: #4CAF50; color: white; border-radius: 15px; padding: 10px 20px; min-width: 50px;}"
            "QPushButton:hover {background-color: #45a049;}"
        )
        protect_btn.clicked.connect(self.on_protect)
        vbox.addWidget(protect_btn, alignment=Qt.AlignCenter)

        # Terminal output
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setStyleSheet("background-color: black; color: white; font-size: 15px; padding: 10px;border-radius: 25px;")
        vbox.addWidget(self.output_text)

        # Set the layout
        self.setLayout(vbox)

    def on_browse(self):
        file_filter = "APK files (*.apk);;All files (*.*)"
        apk_file, _ = QFileDialog.getOpenFileName(self, "Select APK file", "", file_filter)
        if apk_file:
            self.apk_text.setText(apk_file)

    def on_radio_change(self):
        radio = self.sender()
        if radio.isChecked():
            self.selected_operation = radio.text()

    def on_protect(self):
        apk_file = self.apk_text.text().strip()
        if not apk_file:
            QMessageBox.warning(self, "Warning", "Please select an APK file first.")
            return

        if self.encrypt_radio.isChecked():
            self.encrypt_apk(apk_file)
        elif self.decrypt_radio.isChecked():
            self.decrypt_apk(apk_file)
        elif self.delete_radio.isChecked():
            self.delete_apk(apk_file)
        else:
            QMessageBox.warning(self, "Warning", "Please select an operation.")

    def encrypt_apk(self, apk_file):
        self.output_text.clear()
        self.output_text.append("Encrypting APK...")
        self.run_process(["dexprotector", "-encryptApk", apk_file])

    def decrypt_apk(self, apk_file):
        self.output_text.clear()
        self.output_text.append("Decrypting APK...")
        self.run_process(["dexprotector", "-decryptApk", apk_file])

    def delete_apk(self, apk_file):
        self.output_text.clear()
        self.output_text.append("Deleting APK...")
        os.remove(apk_file)
        self.output_text.append(f"{apk_file} deleted successfully.")

    def run_process(self, command):
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        if stdout:
            self.output_text.append(stdout.decode())
        if stderr:
            self.output_text.append(stderr.decode())

    def show_terminal(self):
        self.terminal_window = Window()
        self.terminal_window.show()

    def closeEvent(self, event):
        result = QMessageBox.question(self, "Confirmation", "Are you sure you want to exit?", QMessageBox.Yes | QMessageBox.No)
        if result == QMessageBox.Yes:
            event.accept()
        else:
            event.ignore()

if __name__ == "__main__":
    import sys
    app = QApplication(sys.argv)
    license_window = LicenseWindow()
    license_window.show()
    sys.exit(app.exec_())
