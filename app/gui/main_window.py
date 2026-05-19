from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from app.config.settings import DB_PATH, PRIVATE_KEY_PATH, ensure_data_dirs
from app.error_messages import user_error_message
from app.services.audit_service import get_audit_entries, init_audit_log
from app.services.contact_service import (
    get_all_contacts,
    import_contact_key,
    init_contact_book,
    mark_contact_verified,
)
from app.services.file_crypto_service import decrypt_received_file, encryption_preflight, encrypt_file_for_recipient
from app.services.key_service import export_public_key_qr, export_user_public_key, initialize_user_key


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        ensure_data_dirs()
        init_contact_book(DB_PATH)
        init_audit_log(DB_PATH)

        self.setWindowTitle("EFE - Encrypted File Exchange")
        self.resize(980, 680)

        self.contacts: list[dict] = []
        self.encrypt_input_path: Path | None = None
        self.decrypt_input_path: Path | None = None

        tabs = QTabWidget()
        tabs.addTab(self._build_keys_tab(), "Keys")
        tabs.addTab(self._build_contacts_tab(), "Contacts")
        tabs.addTab(self._build_encrypt_tab(), "Encrypt")
        tabs.addTab(self._build_decrypt_tab(), "Decrypt")
        tabs.addTab(self._build_audit_tab(), "Audit Log")
        self.setCentralWidget(tabs)

        self.statusBar().showMessage("Ready")
        self.refresh_all()

    def _build_notice_box(self) -> QGroupBox:
        box = QGroupBox("Security reminders")
        layout = QVBoxLayout(box)
        for text in [
            "Public keys may be shared.",
            "Private keys must never be shared.",
            "Losing the private key/passphrase may make files unrecoverable.",
            "Fingerprints should be verified before trusting a contact.",
            "EFE is still an MVP and has not been independently audited.",
        ]:
            layout.addWidget(QLabel(text))
        return box

    def _build_keys_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.addWidget(self._build_notice_box())

        self.key_status_label = QLabel()
        layout.addWidget(self.key_status_label)

        form = QFormLayout()
        self.display_name_input = QLineEdit()
        self.email_input = QLineEdit()
        self.key_passphrase_input = QLineEdit()
        self.key_passphrase_input.setEchoMode(QLineEdit.Password)
        self.key_confirm_input = QLineEdit()
        self.key_confirm_input.setEchoMode(QLineEdit.Password)
        form.addRow("Display name", self.display_name_input)
        form.addRow("Email", self.email_input)
        form.addRow("Passphrase", self.key_passphrase_input)
        form.addRow("Confirm passphrase", self.key_confirm_input)
        layout.addLayout(form)

        buttons = QHBoxLayout()
        generate_button = QPushButton("Generate Key")
        generate_button.clicked.connect(self.generate_key)
        export_button = QPushButton("Export Public Key")
        export_button.clicked.connect(self.export_public_key)
        export_qr_button = QPushButton("Save Public Key QR")
        export_qr_button.clicked.connect(self.export_public_key_qr)
        buttons.addWidget(generate_button)
        buttons.addWidget(export_button)
        buttons.addWidget(export_qr_button)
        buttons.addStretch()
        layout.addLayout(buttons)
        layout.addStretch()
        return tab

    def _build_contacts_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        buttons = QHBoxLayout()
        import_button = QPushButton("Import Contact Public Key")
        import_button.clicked.connect(self.import_contact)
        verify_button = QPushButton("Mark Selected Contact Verified")
        verify_button.clicked.connect(self.verify_selected_contact)
        buttons.addWidget(import_button)
        buttons.addWidget(verify_button)
        buttons.addStretch()
        layout.addLayout(buttons)

        self.contacts_table = QTableWidget(0, 4)
        self.contacts_table.setHorizontalHeaderLabels(["Display name", "Email", "Fingerprint", "Verified"])
        self.contacts_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.contacts_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.contacts_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.contacts_table)
        return tab

    def _build_encrypt_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        file_row = QHBoxLayout()
        self.encrypt_file_label = QLabel("No file selected")
        pick_button = QPushButton("Choose File")
        pick_button.clicked.connect(self.choose_encrypt_file)
        file_row.addWidget(self.encrypt_file_label)
        file_row.addWidget(pick_button)
        layout.addLayout(file_row)

        self.contact_combo = QComboBox()
        self.contact_combo.currentIndexChanged.connect(self.update_selected_contact_details)
        layout.addWidget(QLabel("Recipient contact"))
        layout.addWidget(self.contact_combo)
        self.selected_contact_label = QLabel("No contact selected")
        self.unverified_warning_label = QLabel()
        self.unverified_warning_label.setStyleSheet("color: #a45b00; font-weight: bold;")
        layout.addWidget(self.selected_contact_label)
        layout.addWidget(self.unverified_warning_label)

        encrypt_button = QPushButton("Encrypt File")
        encrypt_button.clicked.connect(self.encrypt_selected_file)
        layout.addWidget(encrypt_button)
        self.encrypt_result_label = QLabel()
        layout.addWidget(self.encrypt_result_label)
        layout.addStretch()
        return tab

    def _build_decrypt_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        file_row = QHBoxLayout()
        self.decrypt_file_label = QLabel("No .efe file selected")
        pick_button = QPushButton("Choose .efe File")
        pick_button.clicked.connect(self.choose_decrypt_file)
        file_row.addWidget(self.decrypt_file_label)
        file_row.addWidget(pick_button)
        layout.addLayout(file_row)

        form = QFormLayout()
        self.decrypt_passphrase_input = QLineEdit()
        self.decrypt_passphrase_input.setEchoMode(QLineEdit.Password)
        form.addRow("Private key passphrase", self.decrypt_passphrase_input)
        layout.addLayout(form)

        decrypt_button = QPushButton("Decrypt File")
        decrypt_button.clicked.connect(self.decrypt_selected_file)
        layout.addWidget(decrypt_button)
        self.decrypt_result_label = QLabel()
        layout.addWidget(self.decrypt_result_label)
        layout.addStretch()
        return tab

    def _build_audit_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        refresh_button = QPushButton("Refresh")
        refresh_button.clicked.connect(self.refresh_audit_log)
        layout.addWidget(refresh_button)
        self.audit_table = QTableWidget(0, 6)
        self.audit_table.setHorizontalHeaderLabels(["Time", "Action", "File", "Recipient", "Fingerprint", "Status"])
        self.audit_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.audit_table)
        return tab

    def refresh_all(self) -> None:
        self.refresh_key_status()
        self.refresh_contacts()
        self.refresh_audit_log()

    def refresh_key_status(self) -> None:
        if PRIVATE_KEY_PATH.exists():
            self.key_status_label.setText(f"Local private key exists: {PRIVATE_KEY_PATH}")
        else:
            self.key_status_label.setText("No local private key found. Generate a key before decrypting files.")

    def refresh_contacts(self) -> None:
        self.contacts = get_all_contacts(DB_PATH)
        self.contacts_table.setRowCount(len(self.contacts))
        self.contact_combo.blockSignals(True)
        self.contact_combo.clear()
        for row, contact in enumerate(self.contacts):
            values = [
                contact["display_name"],
                contact["email"],
                contact["key_fingerprint"],
                "yes" if contact["verified"] else "no",
            ]
            for col, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                item.setFlags(item.flags() & ~Qt.ItemIsEditable)
                self.contacts_table.setItem(row, col, item)
            self.contact_combo.addItem(f"{contact['display_name']} <{contact['email']}>", contact["email"])
        self.contact_combo.blockSignals(False)
        self.update_selected_contact_details()

    def refresh_audit_log(self) -> None:
        entries = get_audit_entries(DB_PATH)
        self.audit_table.setRowCount(len(entries))
        for row, entry in enumerate(entries):
            values = [
                entry["timestamp"],
                entry["action_type"],
                entry["filename"],
                entry["recipient_email"] or "",
                entry["key_fingerprint"] or "",
                "success" if entry["success"] else "failure",
            ]
            for col, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                item.setFlags(item.flags() & ~Qt.ItemIsEditable)
                self.audit_table.setItem(row, col, item)

    def selected_contact(self) -> dict | None:
        email = self.contact_combo.currentData()
        for contact in self.contacts:
            if contact["email"] == email:
                return contact
        return None

    def selected_contact_from_table(self) -> dict | None:
        row = self.contacts_table.currentRow()
        if row < 0 or row >= len(self.contacts):
            return None
        return self.contacts[row]

    def update_selected_contact_details(self) -> None:
        contact = self.selected_contact()
        if not contact:
            self.selected_contact_label.setText("No contact selected")
            self.unverified_warning_label.setText("")
            return
        self.selected_contact_label.setText(f"Fingerprint: {contact['key_fingerprint']}")
        if contact["verified"]:
            self.unverified_warning_label.setText("Contact key is verified.")
        else:
            self.unverified_warning_label.setText("Warning: this contact key is unverified.")

    def generate_key(self) -> None:
        display_name = self.display_name_input.text().strip()
        email = self.email_input.text().strip()
        passphrase = self.key_passphrase_input.text()
        confirmation = self.key_confirm_input.text()
        if not display_name or not email:
            self.show_error("Display name and email are required.")
            return
        if passphrase != confirmation:
            self.show_error("Passphrases do not match.")
            return
        if not passphrase:
            self.show_error("Passphrase cannot be empty.")
            return
        try:
            record = initialize_user_key(display_name, email, passphrase.encode("utf-8"))
            self.show_info("Key created", f"Public key fingerprint:\n{record['key_fingerprint']}")
            self.key_passphrase_input.clear()
            self.key_confirm_input.clear()
            self.refresh_key_status()
        except Exception as exc:
            self.show_error(user_error_message(exc))

    def export_public_key(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Export Public Key", "efe-public-key.json", "JSON files (*.json)")
        if not path:
            return
        try:
            exported_path = export_user_public_key(Path(path))
            self.show_info("Public key exported", f"Saved to:\n{exported_path}")
        except Exception as exc:
            self.show_error(user_error_message(exc))

    def export_public_key_qr(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Save Public Key QR", "efe-public-key.png", "PNG files (*.png)")
        if not path:
            return
        try:
            result = export_public_key_qr(Path(path))
            self.show_info(
                "Public key QR saved",
                "The QR contains only the public key record.\n"
                "Recipients should still verify the fingerprint before trusting it.\n\n"
                f"Fingerprint:\n{result['key_fingerprint']}\n\nSaved to:\n{result['output_path']}",
            )
        except Exception as exc:
            self.show_error(user_error_message(exc))

    def import_contact(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Import Contact Public Key", "", "JSON files (*.json)")
        if not path:
            return
        try:
            record = import_contact_key(Path(path), verified=False, db_path=DB_PATH)
            self.show_info(
                "Contact key imported",
                "Verify this fingerprint through another channel before trusting it:\n"
                f"{record['key_fingerprint']}",
            )
            self.refresh_contacts()
        except Exception as exc:
            self.show_error(user_error_message(exc))

    def verify_selected_contact(self) -> None:
        contact = self.selected_contact_from_table()
        if not contact:
            self.show_error("Select a contact first.")
            return
        message = (
            "Only mark this contact verified after checking the fingerprint through another channel.\n\n"
            f"{contact['key_fingerprint']}"
        )
        if QMessageBox.question(self, "Verify contact key", message) != QMessageBox.Yes:
            return
        try:
            mark_contact_verified(contact["email"], DB_PATH)
            self.refresh_contacts()
            self.show_info("Contact verified", f"{contact['email']} is now marked verified.")
        except Exception as exc:
            self.show_error(user_error_message(exc))

    def choose_encrypt_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Choose File to Encrypt")
        if path:
            self.encrypt_input_path = Path(path)
            self.encrypt_file_label.setText(str(self.encrypt_input_path))

    def choose_decrypt_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Choose .efe File", "", "EFE files (*.efe);;All files (*)")
        if path:
            self.decrypt_input_path = Path(path)
            self.decrypt_file_label.setText(str(self.decrypt_input_path))

    def encrypt_selected_file(self) -> None:
        contact = self.selected_contact()
        if not self.encrypt_input_path:
            self.show_error("Choose a file to encrypt first.")
            return
        if not contact:
            self.show_error("Choose a recipient contact first.")
            return
        try:
            preflight = encryption_preflight(self.encrypt_input_path, contact["email"], db_path=DB_PATH)
            if not preflight["recipient_verified"]:
                message = (
                    "This contact key is unverified. Verify the fingerprint before trusting this key.\n\n"
                    f"{preflight['recipient_key_fingerprint']}\n\nEncrypt anyway?"
                )
                if QMessageBox.warning(self, "Unverified contact", message, QMessageBox.Yes | QMessageBox.No) != QMessageBox.Yes:
                    return
            result = encrypt_file_for_recipient(self.encrypt_input_path, contact["email"], db_path=DB_PATH)
            self.encrypt_result_label.setText(f"Encrypted file written to: {result['output_path']}")
            self.refresh_audit_log()
        except Exception as exc:
            self.show_error(user_error_message(exc))

    def decrypt_selected_file(self) -> None:
        if not self.decrypt_input_path:
            self.show_error("Choose a .efe file to decrypt first.")
            return
        passphrase = self.decrypt_passphrase_input.text()
        if not passphrase:
            self.show_error("Private key passphrase is required.")
            return
        try:
            result = decrypt_received_file(self.decrypt_input_path, passphrase.encode("utf-8"), db_path=DB_PATH)
            self.decrypt_result_label.setText(f"Decrypted file written to: {result['output_path']}")
            self.decrypt_passphrase_input.clear()
            self.refresh_audit_log()
        except Exception as exc:
            self.show_error(user_error_message(exc))

    def show_error(self, message: str) -> None:
        self.statusBar().showMessage(message)
        QMessageBox.critical(self, "EFE", message)

    def show_info(self, title: str, message: str) -> None:
        self.statusBar().showMessage(message)
        QMessageBox.information(self, title, message)
