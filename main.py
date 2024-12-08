import sys  
import sqlite3  
import hashlib  
import secrets  
import string  
import base64  
from datetime import datetime  
from cryptography.fernet import Fernet  
from cryptography.hazmat.primitives import hashes  
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,   
                            QHBoxLayout, QPushButton, QLineEdit, QLabel,   
                            QStackedWidget, QTableWidget, QTableWidgetItem,   
                            QHeaderView, QMessageBox, QDialog, QFormLayout,  
                            QSlider, QCheckBox, QInputDialog, QFileDialog)  
from PyQt6.QtCore import Qt, QSize  
from PyQt6.QtGui import QIcon, QFont, QPalette, QColor  
import qdarktheme  
from qt_material import apply_stylesheet 
from cryptography.hazmat.backends import default_backend   

class PasswordManager:  
    def __init__(self, db_path="password_manager.db"):  
        self.db_path = db_path  
        self.master_key = None  
        self.fernet = None  
        self.setup_database()  

    def setup_database(self):  
        conn = sqlite3.connect(self.db_path)  
        cursor = conn.cursor()  

        # Create master_password table if it doesn't exist  
        cursor.execute('''  
        CREATE TABLE IF NOT EXISTS master_password  
        (salt TEXT, password_hash TEXT)  
        ''')  

        # Create passwords table if it doesn't exist  
        cursor.execute('''  
        CREATE TABLE IF NOT EXISTS passwords  
        (id INTEGER PRIMARY KEY,  
        service TEXT,  
        username TEXT,  
        encrypted_password TEXT,  
        created_date TEXT,  
        last_modified TEXT)  
        ''')  

        # Add missing columns if they don't exist  
        try:  
            cursor.execute("ALTER TABLE passwords ADD COLUMN created_date TEXT")  
        except sqlite3.OperationalError:  
            # Column already exists  
            pass  

        try:  
            cursor.execute("ALTER TABLE passwords ADD COLUMN last_modified TEXT")  
        except sqlite3.OperationalError:  
            # Column already exists  
            pass  

        conn.commit()  
        conn.close()    

    def generate_key(self, master_password: str, salt: bytes = None) -> tuple:  
        try:  
            if salt is None:  
                salt = secrets.token_bytes(16)  # Generate 16 bytes of random salt  

            if not isinstance(salt, bytes):  
                raise ValueError("Salt must be bytes")  

            kdf = PBKDF2HMAC(  
                algorithm=hashes.SHA256(),  
                length=32,  
                salt=salt,  
                iterations=100000,  
                backend=default_backend()  # Add this line  
            )  

            key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))  
            return key, salt  
        except Exception as e:  
            print(f"Error in generate_key: {str(e)}")  # Debug print  
            return None, None  

    def setup_master_password(self, master_password: str):  
        try:  
            key, salt = self.generate_key(master_password)  
            if key is None or salt is None:  
                raise ValueError("Failed to generate key and salt")  

            password_hash = hashlib.sha256(master_password.encode()).hexdigest()  

            conn = sqlite3.connect(self.db_path)  
            cursor = conn.cursor()  
            cursor.execute('DELETE FROM master_password')  
            cursor.execute('INSERT INTO master_password (salt, password_hash) VALUES (?, ?)',  
                        (base64.b64encode(salt).decode(), password_hash))  
            conn.commit()  
            conn.close()  

            self.master_key = key  
            self.fernet = Fernet(key)  
        except Exception as e:  
            print(f"Error in setup_master_password: {str(e)}")  # Debug print  
            raise ValueError(f"Failed to setup master password: {str(e)}")  

    def verify_master_password(self, master_password: str) -> bool:  
        conn = sqlite3.connect(self.db_path)  
        cursor = conn.cursor()  
        cursor.execute('SELECT salt, password_hash FROM master_password')  
        result = cursor.fetchone()  
        conn.close()  

        if result:  
            salt = base64.b64decode(result[0])  
            stored_hash = result[1]  
            password_hash = hashlib.sha256(master_password.encode()).hexdigest()  

            if password_hash == stored_hash:  
                key, _ = self.generate_key(master_password, salt)  
                self.master_key = key  
                self.fernet = Fernet(key)  # Set the encryption key  
                return True  
        return False    

    def add_password(self, service: str, username: str, password: str):  
        if not self.fernet:  
            raise Exception("Please login first")  

        encrypted_password = self.fernet.encrypt(password.encode())  
        current_time = datetime.now().isoformat()  

        conn = sqlite3.connect(self.db_path)  
        cursor = conn.cursor()  
        cursor.execute('''  
        INSERT INTO passwords (service, username, encrypted_password, created_date, last_modified)  
        VALUES (?, ?, ?, ?, ?)  
        ''', (service, username, encrypted_password, current_time, current_time))  
        conn.commit()  
        conn.close()  

    def get_all_passwords(self) -> list:  
        if not self.fernet:  
            raise Exception("Please login first")  

        conn = sqlite3.connect(self.db_path)  
        cursor = conn.cursor()  
        cursor.execute('SELECT id, service, username, encrypted_password, created_date, last_modified FROM passwords')  
        results = cursor.fetchall()  
        conn.close()  

        decrypted_results = []  
        for id, service, username, encrypted_password, created, modified in results:  
            decrypted_password = self.fernet.decrypt(encrypted_password).decode()  
            decrypted_results.append({  
                'id': id,  
                'service': service,  
                'username': username,  
                'password': decrypted_password,  
                'created_date': created,  
                'last_modified': modified  
            })  

        return decrypted_results  

    def delete_password(self, password_id: int):  
        if not self.fernet:  
            raise Exception("Please login first")  

        conn = sqlite3.connect(self.db_path)  
        cursor = conn.cursor()  
        cursor.execute('DELETE FROM passwords WHERE id = ?', (password_id,))  
        conn.commit()  
        conn.close()  

    def update_password(self, password_id: int, service: str, username: str, password: str):  
        if not self.fernet:  
            raise Exception("Please login first")  

        encrypted_password = self.fernet.encrypt(password.encode())  
        current_time = datetime.now().isoformat()  

        conn = sqlite3.connect(self.db_path)  
        cursor = conn.cursor()  
        cursor.execute('''  
        UPDATE passwords   
        SET service = ?, username = ?, encrypted_password = ?, last_modified = ?  
        WHERE id = ?  
        ''', (service, username, encrypted_password, current_time, password_id))  
        conn.commit()  
        conn.close()  

    def generate_password(self, length=16, use_uppercase=True, use_numbers=True, use_special=True):  
    # Construct character set based on options  
        characters = string.ascii_lowercase  
        if use_uppercase:  
            characters += string.ascii_uppercase  
        if use_numbers:  
            characters += string.digits  
        if use_special:  
            characters += string.punctuation  

        # Generate password ensuring complexity  
        password = []  
        # Guarantee at least one character from each selected set  
        if use_uppercase:  
            password.append(secrets.choice(string.ascii_uppercase))  
        if use_numbers:  
            password.append(secrets.choice(string.digits))  
        if use_special:  
            password.append(secrets.choice(string.punctuation))  

        # Fill remaining length randomly  
        while len(password) < length:  
            password.append(secrets.choice(characters))  

        # Randomize final password arrangement  
        secrets.SystemRandom().shuffle(password)  

        return ''.join(password)   

    def export_database(self, export_path: str):  
        if not self.fernet:  
            raise Exception("Please login first")  

        import shutil  
        shutil.copy2(self.db_path, export_path)  

    def import_database(self, import_path: str):  
        if not self.fernet:  
            raise Exception("Please login first")  

        import shutil  
        shutil.copy2(import_path, self.db_path)  
        
class ModernButton(QPushButton):  
    def __init__(self, text="", icon_name=None, parent=None):  
        super().__init__(text, parent)  
        self.setFixedHeight(40)  
        self.setFont(QFont("Segoe UI", 10))  
        self.setStyleSheet("""  
            QPushButton {  
                background-color: #0078d4;  
                color: white;  
                border: none;  
                border-radius: 5px;  
                padding: 5px 15px;  
                text-align: left;  
            }  
            QPushButton:hover {  
                background-color: #106ebe;  
            }  
            QPushButton:pressed {  
                background-color: #005a9e;  
            }  
        """)  

class ModernLineEdit(QLineEdit):  
    def __init__(self, parent=None, is_password=False):  
        super().__init__(parent)  
        self.setFixedHeight(40)  
        self.setFont(QFont("Segoe UI", 10))  
        if is_password:  
            self.setEchoMode(QLineEdit.EchoMode.Password)  
        self.setStyleSheet("""  
            QLineEdit {  
                border: 2px solid #e0e0e0;  
                border-radius: 5px;  
                padding: 5px 10px;  
                background-color: white;  
                color:black;
            }  
            QLineEdit:focus {  
                border: 2px solid #0078d4;  
            }  
        """)  

class PasswordDialog(QDialog):  
    def __init__(self, parent=None, password_data=None):  
        super().__init__(parent)  
        self.setWindowTitle("Password Details")  
        self.setModal(True)  
        self.setup_ui(password_data)  

    def setup_ui(self, password_data):
        layout = QVBoxLayout(self)
        form_layout = QFormLayout()

        self.service_input = ModernLineEdit()
        self.username_input = ModernLineEdit()

        # Create a horizontal layout for password input and peek button
        password_layout = QHBoxLayout()
        self.password_input = ModernLineEdit(is_password=True)
        self.peek_button = ModernButton("👁️")
        self.peek_button.setFixedWidth(40)
        self.peek_button.pressed.connect(self.show_password)
        self.peek_button.released.connect(self.hide_password)
        password_layout.addWidget(self.password_input)
        password_layout.addWidget(self.peek_button)

        if password_data:
            self.service_input.setText(password_data['service'])
            self.username_input.setText(password_data['username'])
            self.password_input.setText(password_data['password'])

        form_layout.addRow("Service:", self.service_input)
        form_layout.addRow("Username:", self.username_input)
        form_layout.addRow("Password:", password_layout)

        layout.addLayout(form_layout)

        buttons_layout = QHBoxLayout()
        save_btn = ModernButton("Save")
        save_btn.clicked.connect(self.accept)
        cancel_btn = ModernButton("Cancel")
        cancel_btn.clicked.connect(self.reject)

        buttons_layout.addWidget(save_btn)
        buttons_layout.addWidget(cancel_btn)
        layout.addLayout(buttons_layout)

    def show_password(self):
        self.password_input.setEchoMode(QLineEdit.EchoMode.Normal)

    def hide_password(self):
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)

    def get_values(self):
        return {
            'service': self.service_input.text(),
            'username': self.username_input.text(),
            'password': self.password_input.text()
        }
 

class LoginWindow(QWidget):  
    def __init__(self, password_manager, main_window):  
        super().__init__()  
        self.password_manager = password_manager  
        self.main_window = main_window  
        self.setup_ui()  
        self.setWindowTitle("Password Manager - Login")  

    def setup_ui(self):  
        layout = QVBoxLayout()  
        layout.setSpacing(20)  
        layout.setContentsMargins(50, 50, 50, 50)  

        # Title  
        title = QLabel("🔐 Password Manager")  
        title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))  
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)  
        layout.addWidget(title)  

        # Master Password Input  
        self.master_password = ModernLineEdit(is_password=True)  
        self.master_password.setPlaceholderText("Enter Master Password")  
        self.master_password.returnPressed.connect(self.login)  
        layout.addWidget(self.master_password)  

        # Login Button  
        login_btn = ModernButton("Login")  
        login_btn.clicked.connect(self.login)  
        layout.addWidget(login_btn)  

        # Setup New Button  
        setup_btn = ModernButton("Setup New Password Manager")  
        setup_btn.clicked.connect(self.setup_new)  
        layout.addWidget(setup_btn)  

        layout.addStretch()  
        self.setLayout(layout)  

    def login(self):  
        if self.password_manager.verify_master_password(self.master_password.text()):  
            self.main_window.show()  
            self.main_window.refresh_password_list()  # Refresh the password list after login  
            self.close()  
        else:  
            QMessageBox.warning(self, "Error", "Invalid master password!")  
    def setup_new(self):  
        password, ok = QInputDialog.getText(  
            self, 'Setup New Password Manager',  
            'Enter new master password:',  
            QLineEdit.EchoMode.Password  
        )  
        if ok and password:  
            confirm_password, ok = QInputDialog.getText(  
                self, 'Confirm Password',  
                'Confirm master password:',  
                QLineEdit.EchoMode.Password  
            )  
            if ok and password == confirm_password:  
                self.password_manager.setup_master_password(password)  
                QMessageBox.information(self, "Success", "Password manager setup complete!")  
            else:  
                QMessageBox.warning(self, "Error", "Passwords do not match!")  

class MainWindow(QMainWindow):  
    def __init__(self, password_manager):  
        super().__init__()  
        self.password_manager = password_manager  # Use the shared PasswordManager instance  
        self.setup_ui()  
        self.setWindowTitle("Password Manager")  

    def setup_ui(self):  
        self.setMinimumSize(1000, 600)  
        central_widget = QWidget()  
        self.setCentralWidget(central_widget)  
        layout = QHBoxLayout(central_widget)  

        # Create sidebar  
        sidebar = self.create_sidebar()  
        layout.addWidget(sidebar)  

        # Create main content area  
        self.content_stack = QStackedWidget()  
        self.setup_content_pages()  
        layout.addWidget(self.content_stack)  

    def create_sidebar(self):  
        sidebar = QWidget()  
        sidebar.setFixedWidth(200)  
        sidebar_layout = QVBoxLayout(sidebar)  
        sidebar_layout.setSpacing(10)  
        sidebar_layout.setContentsMargins(10, 20, 10, 20)  

        buttons = [  
            ("🔑 Passwords", self.show_passwords_page),  
            ("➕ Add New", self.show_add_page),  
            ("🎲 Generator", self.show_generator_page),  
            ("⚙️ Settings", self.show_settings_page)  
        ]  

        for text, slot in buttons:  
            btn = ModernButton(text)  
            btn.clicked.connect(slot)  
            sidebar_layout.addWidget(btn)  

        sidebar_layout.addStretch()  
        return sidebar  
    def setup_content_pages(self):  
        # Passwords list page  
        self.setup_passwords_page()  
        self.setup_add_page()  
        self.setup_generator_page()  
        self.setup_settings_page()  

    def setup_passwords_page(self):  
        page = QWidget()  
        layout = QVBoxLayout(page)  
        layout.setContentsMargins(20, 20, 20, 20)  

        # Search bar  
        search_container = QHBoxLayout()  
        self.search_bar = ModernLineEdit()  
        self.search_bar.setPlaceholderText("🔍 Search passwords...")  
        self.search_bar.textChanged.connect(self.filter_passwords)  
        search_container.addWidget(self.search_bar)  
        layout.addLayout(search_container)  

        # Passwords table  
        self.passwords_table = QTableWidget()  
        self.passwords_table.setColumnCount(5)  
        self.passwords_table.setHorizontalHeaderLabels(["Service", "Username", "Password", "Last Modified", "Actions"])  
        self.passwords_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)  
        layout.addWidget(self.passwords_table)  

        self.content_stack.addWidget(page)  

    def setup_add_page(self):  
        page = QWidget()  
        layout = QFormLayout(page)  
        layout.setContentsMargins(50, 50, 50, 50)  

        self.service_input = ModernLineEdit()  
        self.username_input = ModernLineEdit()  
        self.password_input = ModernLineEdit(is_password=True)  

        layout.addRow("Service:", self.service_input)  
        layout.addRow("Username:", self.username_input)  
        layout.addRow("Password:", self.password_input)  

        buttons_layout = QHBoxLayout()  

        # Change this line:  
        generate_btn = ModernButton("🎲 Generate Password")  
        generate_btn.clicked.connect(self.generate_password_from_options)  # Changed from self.generate_password  
        buttons_layout.addWidget(generate_btn)  

        add_btn = ModernButton("💾 Save Password")  
        add_btn.clicked.connect(self.add_password)  
        buttons_layout.addWidget(add_btn)  

        layout.addRow("", buttons_layout)  
        self.content_stack.addWidget(page)    

    def setup_generator_page(self):  
        page = QWidget()  
        layout = QVBoxLayout(page)  
        layout.setContentsMargins(50, 50, 50, 50)  

        # Password length controls  
        length_layout = QHBoxLayout()  
        self.length_label = QLabel("Password Length: 16")  
        self.length_slider = QSlider(Qt.Orientation.Horizontal)  
        self.length_slider.setMinimum(8)  
        self.length_slider.setMaximum(32)  
        self.length_slider.setValue(16)  
        self.length_slider.valueChanged.connect(self.update_length_label)  
        length_layout.addWidget(self.length_label)  
        length_layout.addWidget(self.length_slider)  
        layout.addLayout(length_layout)  

        # Character options  
        self.uppercase_check = QCheckBox("Include Uppercase Letters")  
        self.numbers_check = QCheckBox("Include Numbers")  
        self.special_check = QCheckBox("Include Special Characters")  

        for checkbox in [self.uppercase_check, self.numbers_check, self.special_check]:  
            checkbox.setChecked(True)  
            layout.addWidget(checkbox)  

        # Generate button and result  
        generate_btn = ModernButton("🎲 Generate Password")  
        generate_btn.clicked.connect(self.generate_password_from_options)  
        layout.addWidget(generate_btn)  

        self.generated_password = ModernLineEdit()  
        self.generated_password.setReadOnly(True)  
        layout.addWidget(self.generated_password)  

        # Copy button  
        copy_btn = ModernButton("📋 Copy to Clipboard")  
        copy_btn.clicked.connect(self.copy_generated_password)  
        layout.addWidget(copy_btn)  

        layout.addStretch()  
        self.content_stack.addWidget(page)  

    def setup_settings_page(self):  
        page = QWidget()  
        layout = QVBoxLayout(page)  
        layout.setContentsMargins(50, 50, 50, 50)  

        # Theme selection  
        theme_label = QLabel("Theme")  
        theme_label.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))  
        layout.addWidget(theme_label)  

        theme_btn = ModernButton("🌓 Toggle Dark/Light Mode")  
        theme_btn.clicked.connect(self.toggle_theme)  
        layout.addWidget(theme_btn)  

        # Database management  
        db_label = QLabel("Database Management")  
        db_label.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))  
        layout.addWidget(db_label)  

        export_btn = ModernButton("📤 Export Database")  
        export_btn.clicked.connect(self.export_database)  
        layout.addWidget(export_btn)  

        import_btn = ModernButton("📥 Import Database")  
        import_btn.clicked.connect(self.import_database)  
        layout.addWidget(import_btn)  

        # Change master password  
        password_label = QLabel("Security")  
        password_label.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))  
        layout.addWidget(password_label)  

        change_password_btn = ModernButton("🔑 Change Master Password")  
        change_password_btn.clicked.connect(self.change_master_password)  
        layout.addWidget(change_password_btn)  

        layout.addStretch()  
        self.content_stack.addWidget(page)  

    def show_passwords_page(self):  
        self.content_stack.setCurrentIndex(0)  
        self.refresh_password_list()  

    def show_add_page(self):  
        self.content_stack.setCurrentIndex(1)  

    def show_generator_page(self):  
        self.content_stack.setCurrentIndex(2)  

    def show_settings_page(self):  
        self.content_stack.setCurrentIndex(3)  

    def refresh_password_list(self):  
        self.passwords_table.setRowCount(0)  
        try:  
            passwords = self.password_manager.get_all_passwords()  
            for password in passwords:  
                row = self.passwords_table.rowCount()  
                self.passwords_table.insertRow(row)  

                self.passwords_table.setItem(row, 0, QTableWidgetItem(password['service']))  
                self.passwords_table.setItem(row, 1, QTableWidgetItem(password['username']))  
                self.passwords_table.setItem(row, 2, QTableWidgetItem('••••••••'))  
                self.passwords_table.setItem(row, 3, QTableWidgetItem(password['last_modified']))  

                actions_widget = QWidget()  
                actions_layout = QHBoxLayout(actions_widget)  
                actions_layout.setContentsMargins(0, 0, 0, 0)  

                view_btn = ModernButton("👁️")  
                edit_btn = ModernButton("✏️")  
                delete_btn = ModernButton("🗑️")  

                view_btn.clicked.connect(lambda _, p=password: self.view_password(p))  
                edit_btn.clicked.connect(lambda _, p=password: self.edit_password(p))  
                delete_btn.clicked.connect(lambda _, p=password: self.delete_password(p))  

                for btn in [view_btn, edit_btn, delete_btn]:  
                    btn.setFixedWidth(40)  
                    actions_layout.addWidget(btn)  

                self.passwords_table.setCellWidget(row, 4, actions_widget)  

        except Exception as e:  
            QMessageBox.warning(self, "Error", str(e))  

    def filter_passwords(self):  
        search_text = self.search_bar.text().lower()  
        for row in range(self.passwords_table.rowCount()):  
            show = False  
            for col in range(2):  # Search in service and username columns  
                item = self.passwords_table.item(row, col)  
                if item and search_text in item.text().lower():  
                    show = True  
                    break  
            self.passwords_table.setRowHidden(row, not show)  

    def add_password(self):  
        service = self.service_input.text()  
        username = self.username_input.text()  
        password = self.password_input.text()  

        if service and username and password:  
            try:  
                self.password_manager.add_password(service, username, password)  
                QMessageBox.information(self, "Success", "Password added successfully!")  
                self.service_input.clear()  
                self.username_input.clear()  
                self.password_input.clear()  
                self.show_passwords_page()  
            except Exception as e:  
                QMessageBox.warning(self, "Error", str(e))  
        else:  
            QMessageBox.warning(self, "Error", "Please fill in all fields!")  

    def generate_password_from_options(self):  
        length = self.length_slider.value()  
        password = self.password_manager.generate_password(
            length=length,  
            use_uppercase=self.uppercase_check.isChecked(),  
            use_numbers=self.numbers_check.isChecked(),  
            use_special=self.special_check.isChecked()
        )
        self.generated_password.setText(password)
  
    # In the PasswordManager class, add this method:  
    # In MainWindow class  
    def generate_password_from_options(self):  
        length = self.length_slider.value()  
        password = self.password_manager.generate_password(  
            length=length,  
            use_uppercase=self.uppercase_check.isChecked(),  
            use_numbers=self.numbers_check.isChecked(),  
            use_special=self.special_check.isChecked()  
        )  
        self.generated_password.setText(password)     
    def copy_generated_password(self):  
        QApplication.clipboard().setText(self.generated_password.text())  
        QMessageBox.information(self, "Success", "Password copied to clipboard!")  

    def update_length_label(self):  
        self.length_label.setText(f"Password Length: {self.length_slider.value()}")  

    def view_password(self, password_data):  
        dialog = PasswordDialog(self, password_data)  
        dialog.setWindowTitle("View Password")  
        for input_field in [dialog.service_input, dialog.username_input, dialog.password_input]:  
            input_field.setReadOnly(True)  
        dialog.exec()  

    def edit_password(self, password_data):  
        dialog = PasswordDialog(self, password_data)  
        dialog.setWindowTitle("Edit Password")  
        if dialog.exec() == QDialog.DialogCode.Accepted:  
            new_data = dialog.get_values()  
            try:  
                self.password_manager.update_password(  
                    password_data['id'],  
                    new_data['service'],  
                    new_data['username'],  
                    new_data['password']  
                )  
                self.refresh_password_list()  
                QMessageBox.information(self, "Success", "Password updated successfully!")  
            except Exception as e:  
                QMessageBox.warning(self, "Error", str(e))  

    def delete_password(self, password_data):  
        reply = QMessageBox.question(  
            self, "Confirm Deletion",  
            f"Are you sure you want to delete the password for {password_data['service']}?",  
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No  
        )  

        if reply == QMessageBox.StandardButton.Yes:  
            try:  
                self.password_manager.delete_password(password_data['id'])  
                self.refresh_password_list()  
                QMessageBox.information(self, "Success", "Password deleted successfully!")  
            except Exception as e:  
                QMessageBox.warning(self, "Error", str(e))  

    # def toggle_theme(self):  
    #     if self.palette().color(QPalette.ColorRole.Window).lightness() > 128:  
    #         qdarktheme.setup_theme("dark")  
    #     else:  
    #         qdarktheme.setup_theme("light")  

    def export_database(self):  
        file_path, _ = QFileDialog.getSaveFileName(  
            self, "Export Database", "", "Database Files (*.db)"  
        )  
        if file_path:  
            try:  
                self.password_manager.export_database(file_path)  
                QMessageBox.information(self, "Success", "Database exported successfully!")  
            except Exception as e:  
                QMessageBox.warning(self, "Error", f"Failed to export database: {str(e)}")  

    def import_database(self):  
        file_path, _ = QFileDialog.getOpenFileName(  
            self, "Import Database", "", "Database Files (*.db)"  
        )  
        if file_path:  
            try:  
                self.password_manager.import_database(file_path)  
                self.refresh_password_list()  
                QMessageBox.information(self, "Success", "Database imported successfully!")  
            except Exception as e:  
                QMessageBox.warning(self, "Error", f"Failed to import database: {str(e)}")  
    def toggle_theme(self):  
        app = QApplication.instance()  
        if self.palette().color(QPalette.ColorRole.Window).lightness() > 128:  
            # Dark theme  
            palette = QPalette()  
            palette.setColor(QPalette.ColorRole.Window, QColor(53, 53, 53))  
            palette.setColor(QPalette.ColorRole.WindowText, Qt.GlobalColor.white)  
            palette.setColor(QPalette.ColorRole.Base, QColor(25, 25, 25))  
            palette.setColor(QPalette.ColorRole.AlternateBase, QColor(53, 53, 53))  
            palette.setColor(QPalette.ColorRole.ToolTipBase, Qt.GlobalColor.white)  
            palette.setColor(QPalette.ColorRole.ToolTipText, Qt.GlobalColor.white)  
            palette.setColor(QPalette.ColorRole.Text, Qt.GlobalColor.white)  
            palette.setColor(QPalette.ColorRole.Button, QColor(53, 53, 53))  
            palette.setColor(QPalette.ColorRole.ButtonText, Qt.GlobalColor.white)  
            palette.setColor(QPalette.ColorRole.Link, QColor(42, 130, 218))  
            palette.setColor(QPalette.ColorRole.Highlight, QColor(42, 130, 218))  
            palette.setColor(QPalette.ColorRole.HighlightedText, Qt.GlobalColor.black)  
            app.setPalette(palette)  
        else:  
            # Light theme  
            app.setPalette(app.style().standardPalette())
    def change_master_password(self):  
        current_password, ok = QInputDialog.getText(  
            self, "Change Master Password",  
            "Enter current master password:",  
            QLineEdit.EchoMode.Password  
        )  
        if ok and self.password_manager.verify_master_password(current_password):  
            new_password, ok = QInputDialog.getText(  
                self, "Change Master Password",  
                "Enter new master password:",  
                QLineEdit.EchoMode.Password  
            )  
            if ok:  
                confirm_password, ok = QInputDialog.getText(  
                    self, "Change Master Password",  
                    "Confirm new master password:",  
                    QLineEdit.EchoMode.Password  
                )  
                if ok and new_password == confirm_password:  
                    self.password_manager.setup_master_password(new_password)  
                    QMessageBox.information(self, "Success", "Master password changed successfully!")  
                else:  
                    QMessageBox.warning(self, "Error", "Passwords do not match!")  
        else:  
            QMessageBox.warning(self, "Error", "Invalid current password!")  

def main():  
    app = QApplication(sys.argv)  
    app.setStyle('Fusion')  # Use Fusion style for a modern look  

    password_manager = PasswordManager()  # Create a single PasswordManager instance  
    main_window = MainWindow(password_manager)  # Pass it to MainWindow  
    login_window = LoginWindow(password_manager, main_window)  # Pass it to LoginWindow  
    login_window.show()  

    sys.exit(app.exec())  

# And remove the toggle_theme method or modify it to use Qt's built-in dark palette:  
  

if __name__ == "__main__":  
    main()  