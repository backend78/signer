import os
import subprocess
import random
from shutil import which
import string
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QHBoxLayout, QFileDialog,
    QRadioButton, QMessageBox, QDialog ,QCheckBox,QTextEdit
)
from PyQt5.QtGui import QPixmap
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes 
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon 
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *
import threading
import signal
#=============================(terminal)============================
import sys
import os
import signal
import subprocess
import threading
from PyQt5.QtCore import Qt, QObject, pyqtSignal
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QLineEdit, QPushButton, QLabel, QHBoxLayout, QDialog, QCheckBox, QRadioButton, QTextEdit, QMessageBox, QVBoxLayout
from PyQt5.QtGui import QIcon, QPixmap, QTextCursor


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
        self.path = r'C:\Users\ZEYTON\Desktop\workspace\encrypt\ic\logoo.ico'
        self.setWindowIcon(QIcon(self.path))
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
            command = f"python -m {command}"

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


#=============================(end terminal)============================

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
        pixmap = QPixmap(r"C:\Users\ZEYTON\Desktop\workspace\encrypt\ic\03_Lock_0_render.png")  # Replace with your image path
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
        operation_label.setStyleSheet("font-size: 20px; color: black; font-family: Times New Roman;")

        options_layout = QHBoxLayout()

        self.encrypt_radio = QRadioButton('📔 Encrypt APK 📔')
        self.dex_protect_radio = QRadioButton('📕 Dex Protection 📕')
        self.dex_protect_radio.clicked.connect(self.show_dex_protection_options)
        self.playprotect_bypass_radio = QRadioButton('🛡️ Sign the app 🛡️')
        self.extract_source_code_radio = QRadioButton('📗 Extract source code 📗')

        options_layout.addWidget(self.encrypt_radio)
        options_layout.addWidget(self.dex_protect_radio)
        options_layout.addWidget(self.playprotect_bypass_radio)
        options_layout.addWidget(self.extract_source_code_radio)

        start_operations_btn = QPushButton('Start Operations ♻️')
        start_operations_btn.setFixedWidth(150)
        start_operations_btn.setStyleSheet("QPushButton { border-radius: 15px; background-color: black; color: white; padding: 10px; width:100px; }" "QPushButton:hover {background-color: #141e58;}")
        start_operations_btn.clicked.connect(self.on_start_operations)

        vbox.addWidget(apk_label)
        vbox.addWidget(self.apk_text)
        vbox.addWidget(apk_browse_btn)
        vbox.addWidget(operation_label)
        vbox.addLayout(options_layout)
        vbox.addWidget(start_operations_btn, alignment=Qt.AlignCenter)
        self.set_icon()

        self.terminal_window = Window()  # إنشاء نافذة المحطة الطرفية
        self.output_signal.connect(self.terminal_window.append_output)  # ربط الإشارة بالدالة

    def show_terminal(self):
        self.terminal_window.show()

    def on_browse(self):
        file_dialog = QFileDialog()
        file_dialog.setFileMode(QFileDialog.ExistingFile)
        file_dialog.setNameFilter("APK files (*.apk)")
        if file_dialog.exec_():
            file_paths = file_dialog.selectedFiles()
            self.apk_text.setText(file_paths[0])

            
    def set_icon(self):
        icon_path = os.path.abspath(os.path.join(os.getcwd(), 'ic', 'logoo.ico'))
        self.setWindowIcon(QIcon(icon_path))

    def show_dex_protection_options(self):
        if self.dex_protect_radio.isChecked():
            options = self.get_protection_options()
            dlg = MultiChoiceDialog(options)
            if dlg.exec_():
                selected_options = [checkbox.text() for checkbox in dlg.checkboxes if checkbox.isChecked()]
                selected_options_text = '\n'.join(f"{i+1}. <font color='blue'>{option}</font>" for i, option in enumerate(selected_options))
                QMessageBox.information(self, 'Selected Options', f"Selected options:<br/>{selected_options_text}")

    def get_protection_options(self):
        return ['RandomManifest', 'CallIndirection', 'FieldRename', 'MethodRename', 'ClassRename', 'AddJunkGoto',
                'ArithmeticBranch', 'AssetEncryption', 'EncryptLibraries', 'EncryptRESStrings', 'ObfuscateCodeStrings',
                'AddJunkMethods']

    def on_start_operations(self):
        apk_file_path = self.apk_text.text()
        if not apk_file_path:
            QMessageBox.warning(self, '👽 No APK file selected!', 'Please select an APK file.')
            return

        if self.encrypt_radio.isChecked():
            self.encrypt_apk(apk_file_path)
            QMessageBox.information(self, '✍️ Encryption Success', 'APK file encrypted successfully!')
        elif self.dex_protect_radio.isChecked():
            self.dex_protection()
            QMessageBox.information(self,'🏴 Dex Protection Complete', 'Dex protection applied successfully!')
        elif self.playprotect_bypass_radio.isChecked():
            self.sign_app(apk_file_path)
            QMessageBox.information(self, '🛡️ PlayProtect Bypass Success', 'Sign the app successfully!')
        elif self.extract_source_code_radio.isChecked():
            self.show_terminal()
            QMessageBox.information(self,  '📗 Extraction Converting', 'Please wait until the extraction is finished!')
            self.extract_source_code(apk_file_path)
            QMessageBox.information(self,  '📗 Extraction Complete', 'The source code has been extracted successfully!')

        else:
            QMessageBox.warning(self, '❗ No Operation Selected', 'Please select an operation to perform.')


    def encrypt_apk(self, apk_file_path):
        key, iv = generate_key_and_iv()
        encrypt_file(apk_file_path, "encrypted.apk", key, iv)

    def dex_protection(self):
        selected_options = [checkbox.text() for checkbox in self.findChildren(QCheckBox) if checkbox.isChecked()]
        protection_command = ["dexprotector", "-i", self.apk_text.text(), "-o", "protected.apk"]
        for option in selected_options:
            protection_command.append("--" + option)
        subprocess.run(protection_command)

    
    def sign_app(self, apk_file_path):
        #=================================(devloper)===============================================
        # # تحديد مسارات الأدوات المطلوبة
        # keytool_path = which('keytool')
        # apksigner_path = which('ApkSigner.jar')
        # # التأكد من وجود المسارات
        # if not keytool_path:
        #     QMessageBox.warning(self, 'Missing Tool', 'keytool not found in the system.')
        #     return
        # if not apksigner_path:
        #     QMessageBox.warning(self, 'Missing Tool', 'ApkSigner.jar not found in the system.')
        #     return
        #=================================(devloper)===============================================
        # استخدام الكلاس لتوقيع APK
        try:
            keytool_path = r'C:\Program Files\Java\jre-1.8\bin\keytool.exe'
            apksigner_path = "C:\\Users\\ZEYTON\\Downloads\\APK Easy Tool v1.60 Portable\\Resources\\ApkSigner.jar"
            apk_signer = APKSigner(keytool_path, apksigner_path)
            keystore_path, keystore_password, key_alias_password = apk_signer.create_keystore()
            base_name = os.path.basename(apk_file_path)
            signed_apk_path = os.path.join(os.path.dirname(apk_file_path), base_name.replace('.apk', '-signed.apk'))

            # توقيع APK
            apk_signer.sign_apk(apk_file_path, signed_apk_path, keystore_path, keystore_password, key_alias_password)
            os.remove(which('my-release-key.keystore'))
        except Exception as e:
            print(f"error {e}")

    def extract_source_code(self, apk_file_path):
        self.output_signal.emit("Starting APK extraction process...\n")  # إرسال رسالة البدء إلى المحطة الطرفية
        apk_processor = ApkProcessor()
        user_profile = os.getenv('USERPROFILE')
        decompile_output_dir = os.path.join(user_profile, 'Downloads', 'output_decompiled')
        extract_output_dir = os.path.join(user_profile, 'Downloads', 'output_extractedapk')
        apktool_path = os.path.join(user_profile, 'Downloads', 'APK Easy Tool v1.60 Portable', 'Apktool', 'apktool_2.6.1.jar')
        seven_zip_path = os.path.join(user_profile, 'Downloads', 'APK Easy Tool v1.60 Portable', 'Resources', '7z.exe')
        dex2jar_dir = os.path.join(user_profile, 'Downloads', 'dex-tools-v2.4', 'dex-tools-v2.4')
        jar_output_dir = os.path.join(extract_output_dir, 'jar_files')

        # تمرير دالة المخرجات إلى كل عملية
        apk_processor.decompile_apk(apk_file_path, decompile_output_dir, self.output_signal.emit, apktool_path)
        apk_processor.extract_apk(apk_file_path, extract_output_dir, self.output_signal.emit, seven_zip_path)
        apk_processor.convert_dex_to_jar(extract_output_dir, dex2jar_dir, jar_output_dir, self.output_signal.emit)
        
        

#==================================(Extract source code)======================================
class ApkProcessor():
    def __init__(self):
        pass
    
    @staticmethod
    def decompile_apk(apk_path, output_dir, callback, apktool_path="apktool.jar"):
        try:
            command = [
                "java", "-jar", apktool_path, "d", "-f", "--only-main-classes",
                "-o", output_dir, apk_path
            ]
            # تشغيل الأمر والتقاط المخرجات
            result = subprocess.run(command, text=True, capture_output=True)
            if result.returncode == 0:
                callback("Decompile successful.\n")
                callback(result.stdout)
            else:
                callback("Decompile failed.\n")
                callback(result.stderr)
        except Exception as e:
            callback(f"An error occurred: {e}")

    @staticmethod
    def extract_apk(apk_path, output_dir, callback, seven_zip_path="7z.exe"):
        try:
            command = [
                seven_zip_path, "x", apk_path, f"-o{output_dir}", "-aoa"
            ]
            # تشغيل الأمر والتقاط المخرجات
            result = subprocess.run(command, text=True, capture_output=True)
            if result.returncode == 0:
                callback("Extracting APK successful.\n")
                callback(result.stdout)
            else:
                callback("Extracting APK failed.\n")
                callback(result.stderr)
        except Exception as e:
            callback(f"An error occurred: {e}")

    @staticmethod
    def convert_dex_to_jar(dex_dir, dex2jar_dir, jar_output_dir, callback):
        try:
            if not os.path.exists(dex_dir):
                callback(f"The directory {dex_dir} does not exist.\n")
                return

            if not os.path.exists(jar_output_dir):
                os.makedirs(jar_output_dir)
            
            for file in os.listdir(dex_dir):
                if file.endswith(".dex"):
                    dex_path = os.path.join(dex_dir, file)
                    jar_path = os.path.join(jar_output_dir, os.path.splitext(file)[0] + ".jar")
                    command = [os.path.join(dex2jar_dir, "d2j-dex2jar.bat"), "-o", jar_path, dex_path]
                    result = subprocess.run(command, text=True, capture_output=True)
                    if result.returncode == 0:
                        callback(f"Converted {file} to {os.path.basename(jar_path)} successfully.\n")
                        callback(result.stdout)
                    else:
                        callback(f"Failed to convert {file}.\n")
                        callback(result.stderr)
        except Exception as e:
            callback(f"An error occurred: {e}")
#==================================(end Extract source code)======================================

#==============================(sing)===============================

class APKSigner(QObject):
    output_signal = pyqtSignal(str)  # إشارة جديدة لإرسال المخرجات
    def __init__(self, keytool_path, apksigner_path):
        super().__init__() 
        self.keytool_path = keytool_path
        self.apksigner_path = apksigner_path
        self.country_codes = [
            'AF', 'AX', 'AL', 'DZ', 'AS', 'AD', 'AO', 'AI', 'AQ', 'AG', 'AR',
            'BS', 'BH', 'BD', 'BB', 'BY', 'BE', 'BZ', 'BJ', 'BM', 'BT', 'BO', 'BQ', 'BA', 'BW', 'BV', 'BR',
            'IO', 'BN', 'BG', 'BF', 'BI', 'CV', 'KH', 'CM', 'CA', 'KY', 'CF', 'TD', 'CL', 'CN', 'CX', 'CC',
            'CO', 'KM', 'CG', 'CD', 'CK', 'CR', 'HR', 'CU', 'CW', 'CY', 'CZ', 'DK', 'DJ', 'DM', 'DO', 'EC',
            'EG', 'SV', 'GQ', 'ER', 'EE', 'SZ', 'ET', 'FK', 'FO', 'FJ', 'FI', 'FR', 'GF', 'PF', 'TF', 'GA',
            'GM', 'GE', 'DE', 'GH', 'GI', 'GR', 'GL', 'GD', 'GP', 'GU', 'GT', 'GG', 'GN', 'GW', 'GY', 'HT',
            'HM', 'VA', 'HN', 'HK', 'HU', 'IS', 'IN', 'ID', 'IR', 'IQ', 'IE', 'IM', 'IL', 'IT', 'JM', 'JP',
            'JE', 'JO', 'KZ', 'KE', 'KI', 'KP', 'KR', 'KW', 'KG', 'LA', 'LV', 'LB', 'LS', 'LR', 'LY', 'LI',
            'LT', 'LU', 'MO', 'MG', 'MW', 'MY', 'MV', 'ML', 'MT', 'MH', 'MQ', 'MR', 'MU', 'YT', 'MX', 'FM',
            'MD', 'MC', 'MN', 'ME', 'MS', 'MA', 'MZ', 'MM', 'NA', 'NR', 'NP', 'NL', 'NC', 'NZ', 'NI', 'NE',
            'NG', 'NU', 'NF', 'MK', 'MP', 'NO', 'OM', 'PK', 'PW', 'PS', 'PA', 'PG', 'PY', 'PE', 'PH', 'PN',
            'PL', 'PT', 'PR', 'QA', 'RE', 'RO', 'RU', 'RW', 'BL', 'SH', 'KN', 'LC', 'MF', 'PM', 'VC', 'WS',
            'SM', 'ST', 'SA', 'SN', 'RS', 'SC', 'SL', 'SG', 'SX', 'SK', 'SI', 'SB', 'SO', 'ZA', 'GS', 'SS',
            'ES', 'LK', 'SD', 'SR', 'SJ', 'SE', 'CH', 'SY', 'TW', 'TJ', 'TZ', 'TH', 'TL', 'TG', 'TK', 'TO',
            'TT', 'TN', 'TR', 'TM', 'TC', 'TV', 'UG', 'UA', 'AE', 'GB', 'US', 'UM', 'UY', 'UZ', 'VU', 'VE',
            'VN', 'VG', 'VI', 'WF', 'EH', 'YE', 'ZM', 'ZW', 'AM', 'AW', 'AU', 'AT', 'AZ'
        ]

        self.terminal_window = Window()  # إنشاء نافذة المحطة الطرفية
        self.output_signal.connect(self.terminal_window.append_output)  # ربط الإشارة بالدالة

    def generate_random_string(self, length):
        letters = string.ascii_letters + string.digits
        return ''.join(random.choice(letters) for i in range(length))

    def create_keystore(self):
        # توليد بيانات عشوائية
        first_last_name = self.generate_random_string(5)
        organizational_unit = self.generate_random_string(2)
        organization = self.generate_random_string(2)
        locality = self.generate_random_string(5)
        state_province = self.generate_random_string(5)
        country_code = random.choice(self.country_codes)

        # توليد كلمات مرور عشوائية
        keystore_password = self.generate_random_string(10)
        key_alias_password = self.generate_random_string(10)

        # مسار keystore
        keystore_name = 'my-release-key.keystore'
        keystore_path = os.path.join(os.getcwd(), keystore_name)


        # تنفيذ أمر keytool لإنشاء مفتاح وشهادة موقع بتنسيق JKS
        cmd1 = [
            self.keytool_path, '-genkeypair', '-v', '-keystore', keystore_path, '-keyalg', 'RSA',
            '-keysize', '2048', '-validity', '10000', '-alias', 'my-key-alias', 
            '-dname', f'CN={first_last_name}, OU={organizational_unit}, O={organization}, L={locality}, ST={state_province}, C={country_code}'
        ]

        # تحويل التسلسل إلى مصفوفة بايتات
        input_data_cmd1 = '\n'.join([
            keystore_password, keystore_password, key_alias_password, key_alias_password
        ]).encode()

        # تشغيل الأمر لإنشاء المفتاح والشهادة
        subprocess.run(cmd1, input=input_data_cmd1, shell=True)

        # تنفيذ أمر keytool لتحويل تنسيق المفتاح إلى PKCS12 بدون حفظ نسخة احتياطية
        cmd2 = [
            self.keytool_path, '-importkeystore', '-srckeystore', keystore_path, 
            '-destkeystore', keystore_path, '-deststoretype', 'pkcs12',
            '-srcstorepass', keystore_password, '-deststorepass', keystore_password,
            '-srckeypass', key_alias_password, '-destkeypass', key_alias_password
        ]
          
        # تشغيل الأمر لتحويل تنسيق المفتاح
        subprocess.run(cmd2, shell=True)

        # طباعة كلمات المرور المستخدمة
        print(f'Keystore created with keystore password: {keystore_password} and key alias password: {key_alias_password}')

        # طباعة مسار keystore
        print(keystore_path)

        return keystore_path, keystore_password, key_alias_password

    def sign_apk(self, apk_path, signed_apk_path, keystore_path, keystore_password, key_alias_password):
        try:
            # Command to sign the APK
            command = [
                "java", "-jar", self.apksigner_path, "sign",
                "--ks", keystore_path,
                "--ks-pass", f"pass:{keystore_password}",
                "--key-pass", f"pass:{key_alias_password}",
                "--out", signed_apk_path,
                apk_path
            ]
            result = subprocess.run(command, capture_output=True, text=True)
            print(result.stdout)
            if result.returncode == 0:
                print("Sign successful.")
                
            else:
                print("Sign failed.")
                print(result.stderr)
        except Exception as e:
            print(f"An error occurred: {e}")

    def show_terminal(self):
        self.terminal_window.show()

        
#==============================(end sing)===============================
def generate_key_and_iv():
    key = get_random_bytes(16)
    iv = os.urandom(16)
    return key, iv

def encrypt_file(input_file, output_file, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    with open(input_file, 'rb') as f:
        plaintext = f.read()
    padded_plaintext = pad(plaintext, AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    with open(output_file, 'wb') as f:
        f.write(ciphertext)

def decrypt_file(input_file, output_file, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    with open(input_file, 'rb') as f:
        ciphertext = f.read()
    decrypted_data = cipher.decrypt(ciphertext)
    unpadded_data = unpad(decrypted_data, AES.block_size)
    with open(output_file, 'wb') as f:
        f.write(unpadded_data)




if __name__ == "__main__":
    import sys
    app = QApplication(sys.argv)
    license_window = LicenseWindow()
    license_window.show()
    sys.exit(app.exec_())


