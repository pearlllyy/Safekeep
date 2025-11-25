import sys
from PyQt6 import QtWidgets, QtCore, QtGui
from sign_up import Ui_MainWindow as SignUpUI
from master_pass import Ui_masterPassDialog as MasterPassUI
from main_window import Ui_MainWindow as MainWindowUI
from add_edit import Ui_AddEditDialog as AddEditUI
from view_details import Ui_Viewdetailsdialog as ViewDetailsUI
from connect_databse import ConnectDatabase
import hashlib
import sqlite3


class SignUpWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = SignUpUI()
        self.ui.setupUi(self)
        self.db = ConnectDatabase()
        self.connect_signals()

    def connect_signals(self):
        self.ui.signUpBtn.clicked.connect(self.signup_user)
        self.ui.showPassBtn.clicked.connect(self.toggle_pass_visibility)
        self.ui.showPassBtn_2.clicked.connect(self.toggle_confirm_pass_visibility)

    def toggle_pass_visibility(self):
        if self.ui.passTxt.echoMode() == QtWidgets.QLineEdit.EchoMode.Password:
            self.ui.passTxt.setEchoMode(QtWidgets.QLineEdit.EchoMode.Normal)
        else:
            self.ui.passTxt.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)

    def toggle_confirm_pass_visibility(self):
        if self.ui.confirmPassTxt.echoMode() == QtWidgets.QLineEdit.EchoMode.Password:
            self.ui.confirmPassTxt.setEchoMode(QtWidgets.QLineEdit.EchoMode.Normal)
        else:
            self.ui.confirmPassTxt.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)

    def signup_user(self):
        username = self.ui.usernameTxt.text().strip()
        password = self.ui.passTxt.text()
        confirm_password = self.ui.confirmPassTxt.text()



        if not username or not password:
            QtWidgets.QMessageBox.warning(self, "Error", "Please fill all fields")
            return

        if password != confirm_password:
            QtWidgets.QMessageBox.warning(self, "Error", "Passwords do not match")
            return

        if len(password) < 6:
            QtWidgets.QMessageBox.warning(self, "Error", "Password must be at least 6 characters")
            return

        # Hash password and save to database
        hashed_pass = hashlib.sha256(password.encode()).hexdigest()

        try:
            # Create users table if it doesn't exist
            self.db.cursor.execute('''
                                   CREATE TABLE IF NOT EXISTS users
                                   (
                                       user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                                       username TEXT UNIQUE NOT NULL,
                                       master_password TEXT NOT NULL
                                   )
                                   ''')
            self.db.conn.commit()

            # Insert user
            sql = "INSERT INTO users (username, master_password) VALUES (?, ?)"
            self.db.cursor.execute(sql, (username, hashed_pass))
            self.db.conn.commit()

            QtWidgets.QMessageBox.information(self, "Success", "Account created successfully!")
            self.open_master_pass_window()
        except sqlite3.IntegrityError:
            QtWidgets.QMessageBox.warning(self, "Error", "Username already exists")
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"Failed to save account: {e}")

    def open_master_pass_window(self):
        self.master_pass_window = MasterPassWindow()
        self.master_pass_window.show()
        self.close()


class MasterPassWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = MasterPassUI()
        self.ui.setupUi(self)
        self.db = ConnectDatabase()
        self.connect_signals()
        self.load_username()

    def connect_signals(self):
        self.ui.loginBtn.clicked.connect(self.verify_master_password)
        self.ui.show_masterPassBtn.clicked.connect(self.toggle_pass_visibility)

    def load_username(self):
        try:
            # Get the last created user (most recent)
            self.db.cursor.execute("SELECT username FROM users ORDER BY user_id DESC LIMIT 1")
            result = self.db.cursor.fetchone()
            if result:
                username = result[0]
                self.ui.label_13.setText(f"{username.title()}!")
            else:
                self.ui.label_13.setText("User!")
        except Exception as e:
            print(f"Error loading username: {e}")
            self.ui.label_13.setText("User!")

    def toggle_pass_visibility(self):
        if self.ui.passTxt_2.echoMode() == QtWidgets.QLineEdit.EchoMode.Password:
            self.ui.passTxt_2.setEchoMode(QtWidgets.QLineEdit.EchoMode.Normal)
        else:
            self.ui.passTxt_2.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)

    def verify_master_password(self):
        password = self.ui.passTxt_2.text()

        if not password:
            QtWidgets.QMessageBox.warning(self, "Error", "Please enter password")
            return

        try:
            entered_hash = hashlib.sha256(password.encode()).hexdigest()

            # Get the last created user (most recent)
            self.db.cursor.execute("SELECT user_id, master_password FROM users ORDER BY user_id DESC LIMIT 1")
            result = self.db.cursor.fetchone()

            if result and result[1] == entered_hash:
                self.open_main_window()
            else:
                QtWidgets.QMessageBox.warning(self, "Error", "Incorrect password")
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"Error verifying password: {e}")

    def open_main_window(self):
        self.main_window = MainWindow()
        self.main_window.show()
        self.close()


class AddEditDialog(QtWidgets.QMainWindow):  # Changed from QDialog to QMainWindow
    # Define a custom signal that emits when data is saved (PyQt6 syntax)
    data_saved = QtCore.pyqtSignal()
    
    def __init__(self, db, entry_id=None, parent=None, on_save_callback=None):
        super().__init__(parent)
        self.db = db
        self.entry_id = entry_id
        self.on_save_callback = on_save_callback  # Store callback
        
        # Set window flags to make it behave like a dialog
        self.setWindowFlags(
            QtCore.Qt.WindowType.Dialog |
            QtCore.Qt.WindowType.WindowTitleHint |
            QtCore.Qt.WindowType.WindowCloseButtonHint
        )
        
        self.ui = AddEditUI()
        self.ui.setupUi(self)
        
        self.connect_signals()
        if entry_id:
            self.load_entry_details()

    def connect_signals(self):
        self.ui.saveBtn.clicked.connect(self.save_entry)
        self.ui.generatePassBtn.clicked.connect(self.generate_password)
        self.ui.showPassBtn.clicked.connect(self.toggle_password_visibility)
        self.ui.cancelBtn.clicked.connect(self.close)  # Ensure cancel button works

    def load_entry_details(self):
        try:
            # Ga load ka existing entry details halin sa database gamit ang entry_id mismo
            sql = "SELECT * FROM passwords WHERE pid = ?"
            self.db.cursor.execute(sql, (self.entry_id,))
            entry = self.db.cursor.fetchone()
            # kung may makita nga match entry, i fill na bawat details base sa kung ano naka store sa database, ipagwa na tuya sa add_edit para pwede ma edit.
            if entry:
                self.ui.websiteTxt.setText(entry['title'])
                self.ui.unameTxt.setText(entry['username'] if entry['username'] else '')
                # Handle email - sqlite3.Row doesn't have .get(), use try/except or direct access
                try:
                    email_value = entry['email'] if entry['email'] else ''
                except (KeyError, IndexError):
                    email_value = ''
                self.ui.emailTxt.setText(email_value)
                self.ui.passTxt.setText(entry['password'])
                category = entry['category'] if entry['category'] else 'Development'
                self.ui.categoryCmb.setCurrentText(category)
                self.ui.label_7.setText("Edit Details")
            # Ga show ka error message kung di makita ang entry
            else:
                QtWidgets.QMessageBox.warning(self, "Error", "Entry not found")
        # Ga show ka error message kung may error sa pag load ka entry
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"Failed to load entry: {e}")

    def save_entry(self):
        title = self.ui.websiteTxt.text().strip()
        username = self.ui.unameTxt.text().strip()
        email = self.ui.emailTxt.text().strip()
        password = self.ui.passTxt.text()
        category = self.ui.categoryCmb.currentText()

        if not title or not password:
            QtWidgets.QMessageBox.warning(self, "Error", "Title and Password are required")
            return

        try:
            from datetime import datetime
            last_modified = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            if self.entry_id:
                self.db.update_details(title, username, password, category, last_modified, self.entry_id, email)
                QtWidgets.QMessageBox.information(self, "Success", "Entry updated successfully!")
            else:
                self.db.add_details(title, username, password, category, last_modified, email)
                QtWidgets.QMessageBox.information(self, "Success", "Entry added successfully!")

            # Call callback if provided
            if self.on_save_callback:
                self.on_save_callback()
            
            self.close()
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"Failed to save entry: {e}")

    def generate_password(self):
        import string
        import random
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        password = ''.join(random.choice(chars) for _ in range(12))
        self.ui.passTxt.setText(password)

    def toggle_password_visibility(self):
        if self.ui.passTxt.echoMode() == QtWidgets.QLineEdit.EchoMode.Password:
            self.ui.passTxt.setEchoMode(QtWidgets.QLineEdit.EchoMode.Normal)
        else:
            self.ui.passTxt.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)


class ViewDetailsDialog(QtWidgets.QMainWindow):  # Changed from QDialog to QMainWindow
    def __init__(self, db, entry_id, parent=None):
        super().__init__(parent)
        self.db = db
        self.entry_id = entry_id
        
        # Set window flags to make it behave like a dialog
        self.setWindowFlags(
            QtCore.Qt.WindowType.Dialog |
            QtCore.Qt.WindowType.WindowTitleHint |
            QtCore.Qt.WindowType.WindowCloseButtonHint
        )
        
        self.ui = ViewDetailsUI()
        self.ui.setupUi(self)
        
        self.connect_signals()
        self.load_entry_details()

    def connect_signals(self):
        self.ui.showPassBtn.clicked.connect(self.toggle_password_visibility)
        self.ui.copyPass.clicked.connect(self.copy_to_clipboard)
        self.ui.copyUsername.clicked.connect(self.copy_username)
        self.ui.copyEmail.clicked.connect(self.copy_email)
        self.ui.closeBtn.clicked.connect(self.close)  # Ensure close button works

    def load_entry_details(self):
        # Ga load ka existing entry details halin sa database gamit ang entry_id
        try:
            sql = "SELECT * FROM passwords WHERE pid = ?"
            self.db.cursor.execute(sql, (self.entry_id,))
            entry = self.db.cursor.fetchone()

            # ga load ka sang details sa ui fields
            if entry:
                self.ui.label_7.setText(entry['title']) # ga set ka title sa label
                self.ui.unameTxt.setText(entry['username'] if entry['username'] else '') # ga set ka username
                # Fix: Use actual email field, not username
                try:
                    email_value = entry['email'] if entry['email'] else '' # ga handle ka email kay sqlite3.Row wala .get() para mag kwa ka value
                except (KeyError, IndexError):
                    email_value = ''
                self.ui.emailTxt.setText(email_value) # ga set ka email
                self.ui.passTxt.setText(entry['password'])
                self.ui.categoryTxt.setEchoMode(QtWidgets.QLineEdit.EchoMode.Normal)
                self.ui.categoryTxt.setText(entry['category'] if entry['category'] else '')

        # Ga show ka error message kung indi makita ang entry
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"Failed to load entry: {e}")

    def toggle_password_visibility(self):
        if self.ui.passTxt.echoMode() == QtWidgets.QLineEdit.EchoMode.Password:
            self.ui.passTxt.setEchoMode(QtWidgets.QLineEdit.EchoMode.Normal)
        else:
            self.ui.passTxt.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)

    def copy_to_clipboard(self):
        clipboard = QtWidgets.QApplication.clipboard()
        clipboard.setText(self.ui.passTxt.text())
        QtWidgets.QMessageBox.information(self, "Copied", "Password copied to clipboard!")

    def copy_username(self):
        clipboard = QtWidgets.QApplication.clipboard()
        clipboard.setText(self.ui.unameTxt.text())
        QtWidgets.QMessageBox.information(self, "Copied", "Username copied to clipboard!")

    def copy_email(self):
        clipboard = QtWidgets.QApplication.clipboard()
        clipboard.setText(self.ui.emailTxt.text())
        QtWidgets.QMessageBox.information(self, "Copied", "Email copied to clipboard!")


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = MainWindowUI()
        self.ui.setupUi(self)
        self.db = ConnectDatabase()
        self.add_dialog = None
        self.edit_dialog = None
        self.view_dialog = None
        self.connect_signals()
        self.load_passwords()
        self.update_stats()

    def connect_signals(self):
        self.ui.newpassBtn.clicked.connect(self.open_add_dialog)
        self.ui.categoryList.itemClicked.connect(self.filter_by_category)
        self.ui.searchbar.textChanged.connect(self.search_passwords)
        self.ui.passTable.cellDoubleClicked.connect(self.open_view_details)
        

    def load_passwords(self, category=None):
        try:
            if category and category != "All Passwords":
                sql = "SELECT * FROM passwords WHERE category = ?"
                self.db.cursor.execute(sql, (category,))
            else:
                sql = "SELECT * FROM passwords"
                self.db.cursor.execute(sql)

            results = self.db.cursor.fetchall()
            self.populate_table(results)
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"Failed to load passwords: {e}")

    def populate_table(self, results):
        self.ui.passTable.setRowCount(0)

        for row_idx, entry in enumerate(results):
            self.ui.passTable.insertRow(row_idx)
            self.ui.passTable.setItem(row_idx, 0, QtWidgets.QTableWidgetItem(entry['title']))
            self.ui.passTable.setItem(row_idx, 1, QtWidgets.QTableWidgetItem(entry['username']))
            self.ui.passTable.setItem(row_idx, 2, QtWidgets.QTableWidgetItem(entry['category']))
            self.ui.passTable.setItem(row_idx, 3, QtWidgets.QTableWidgetItem(entry['last_modified']))

            # Action buttons
            actions_widget = QtWidgets.QWidget()
            actions_layout = QtWidgets.QHBoxLayout(actions_widget)
            actions_layout.setContentsMargins(5, 0, 5, 0)
            actions_layout.setSpacing(5)  # Add spacing between buttons

            edit_btn = QtWidgets.QPushButton()
            delete_btn = QtWidgets.QPushButton()
            
            # Set icons
            edit_icon = QtGui.QIcon()
            edit_icon.addPixmap(QtGui.QPixmap("icons/edit.png"), QtGui.QIcon.Mode.Normal, QtGui.QIcon.State.Off)
            edit_btn.setIcon(edit_icon)
            
            delete_icon = QtGui.QIcon()
            delete_icon.addPixmap(QtGui.QPixmap("icons/trash.png"), QtGui.QIcon.Mode.Normal, QtGui.QIcon.State.Off)
            delete_btn.setIcon(delete_icon)
            
            # Optional: Add styles for icon buttons
            edit_btn.setStyleSheet("""
                QPushButton {
                    border: none;
                    background-color: transparent;
                    padding: 5px;
                }
                QPushButton:hover {
                    background-color: #6BACE7;
                    border-radius: 4px;
                }
            """)
            
            delete_btn.setStyleSheet("""
                QPushButton {
                    border: none;
                    background-color: transparent;
                    padding: 5px;
                }
                QPushButton:hover {
                    background-color: #FF5357;
                    border-radius: 4px;
                }
            """)
            
            # Set fixed size
            edit_btn.setFixedSize(40, 30)
            delete_btn.setFixedSize(40, 30)
            
            # Set tooltips so users know what the buttons do
            edit_btn.setToolTip("Edit")
            delete_btn.setToolTip("Delete")
            
            edit_btn.clicked.connect(lambda checked, pid=entry['pid']: self.open_edit_dialog(pid))
            delete_btn.clicked.connect(lambda checked, pid=entry['pid']: self.delete_entry(pid))

            actions_layout.addWidget(edit_btn)
            actions_layout.addWidget(delete_btn)
            self.ui.passTable.setCellWidget(row_idx, 4, actions_widget)

    def open_add_dialog(self):
        self.add_dialog = AddEditDialog(self.db, parent=self, on_save_callback=self.on_dialog_closed)
        self.add_dialog.show()

    def open_edit_dialog(self, entry_id):
        self.edit_dialog = AddEditDialog(self.db, entry_id, parent=self, on_save_callback=self.on_dialog_closed)
        self.edit_dialog.show()

    def on_dialog_closed(self):
        self.load_passwords()
        self.update_stats()

    def open_view_details(self, row, col):
        entry_id = self.ui.passTable.item(row, 0)
        if entry_id:
            sql = "SELECT pid FROM passwords WHERE title = ?"
            self.db.cursor.execute(sql, (entry_id.text(),))
            result = self.db.cursor.fetchone()
            if result:
                self.view_dialog = ViewDetailsDialog(self.db, result['pid'], parent=self)  # Pass self as parent
                self.view_dialog.show()

    def filter_by_category(self, item):
        category = item.text()
        self.load_passwords(category)

    def search_passwords(self, text):
        if not text:
            self.load_passwords()
            return

        try:
            results = self.db.search_passwords(text)  # no "title" argument
            self.populate_table(results)
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"Search failed: {e}")

    def delete_entry(self, entry_id):
        reply = QtWidgets.QMessageBox.question(
            self, "Confirm", "Are you sure you want to delete this entry?",
            QtWidgets.QMessageBox.StandardButton.Yes | QtWidgets.QMessageBox.StandardButton.No
        )
        if reply == QtWidgets.QMessageBox.StandardButton.Yes:
            try:
                sql = "DELETE FROM passwords WHERE pid = ?"
                self.db.cursor.execute(sql, (entry_id,))
                self.db.conn.commit()
                self.load_passwords()
                self.update_stats()
            except Exception as e:
                QtWidgets.QMessageBox.critical(self, "Error", f"Failed to delete: {e}")

    def refresh_table(self):
        self.load_passwords()

    def update_stats(self):
        try:
            self.db.cursor.execute("SELECT COUNT(*) FROM passwords")
            count = self.db.cursor.fetchone()[0]
            self.ui.statsLabel.setText(f"{count} passwords stored")
        except Exception as e:
            print(f"Error updating stats: {e}")


def main():
    app = QtWidgets.QApplication(sys.argv)

    # Check if users table exists and has users
    try:
        db = ConnectDatabase()
        db.cursor.execute("SELECT COUNT(*) FROM users")
        user_count = db.cursor.fetchone()[0]

        if user_count > 0:
            window = MasterPassWindow()
        else:
            window = SignUpWindow()
    except:
        window = SignUpWindow()

    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()