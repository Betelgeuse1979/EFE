from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QFrame,
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

from app.config.settings import DB_PATH, PRIVATE_KEY_PATH, ensure_data_dirs, get_data_paths
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


def _short_fingerprint(fingerprint: str | None) -> str:
    if not fingerprint:
        return ""
    compact = fingerprint.replace(":", "")
    if len(compact) <= 16:
        return fingerprint
    return f"{compact[:8]}...{compact[-8:]}"


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        ensure_data_dirs()
        init_contact_book(DB_PATH)
        init_audit_log(DB_PATH)

        self.setWindowTitle("EFE - Encrypted File Exchange")
        self.resize(1100, 720)

        self.contacts: list[dict] = []
        self.encrypt_input_path: Path | None = None
        self.decrypt_input_path: Path | None = None

        shell = QWidget()
        shell_layout = QVBoxLayout(shell)
        shell_layout.setContentsMargins(18, 16, 18, 14)
        shell_layout.setSpacing(14)
        shell_layout.addWidget(self._build_header())

        tabs = QTabWidget()
        tabs.setDocumentMode(True)
        tabs.addTab(self._build_keys_tab(), "Keys")
        tabs.addTab(self._build_contacts_tab(), "Contacts")
        tabs.addTab(self._build_encrypt_tab(), "Encrypt")
        tabs.addTab(self._build_decrypt_tab(), "Decrypt")
        tabs.addTab(self._build_audit_tab(), "Audit Log")
        shell_layout.addWidget(tabs, 1)
        self.setCentralWidget(shell)

        self.statusBar().showMessage("Ready")
        self.refresh_all()

    def _build_header(self) -> QWidget:
        header = QFrame()
        header.setObjectName("hero")
        layout = QVBoxLayout(header)
        layout.setContentsMargins(18, 14, 18, 14)
        layout.setSpacing(6)

        title = QLabel("Encrypted File Exchange")
        title.setObjectName("title")
        subtitle = QLabel("Encrypt files locally, then attach the encrypted .efe file using your normal email client.")
        subtitle.setObjectName("subtitle")
        reminders = QLabel(
            "Public keys may be shared. Private keys must never be shared. "
            "Verify fingerprints before trusting contacts. EFE is an MVP and has not been independently audited."
        )
        reminders.setObjectName("helper")
        reminders.setWordWrap(True)

        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addWidget(reminders)
        return header

    def _make_page(self, title: str, helper: str) -> tuple[QWidget, QVBoxLayout]:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(14)
        layout.addWidget(self._section_heading(title, helper))
        return page, layout

    def _section_heading(self, title: str, helper: str) -> QWidget:
        box = QWidget()
        layout = QVBoxLayout(box)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)
        title_label = QLabel(title)
        title_label.setObjectName("sectionTitle")
        helper_label = QLabel(helper)
        helper_label.setObjectName("helper")
        helper_label.setWordWrap(True)
        layout.addWidget(title_label)
        layout.addWidget(helper_label)
        return box

    def _group(self, title: str) -> QGroupBox:
        group = QGroupBox(title)
        group.setObjectName("panel")
        return group

    def _set_table_defaults(self, table: QTableWidget) -> None:
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setSelectionMode(QAbstractItemView.SingleSelection)
        table.verticalHeader().setVisible(False)
        table.horizontalHeader().setStretchLastSection(True)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

    def _build_keys_tab(self) -> QWidget:
        tab, layout = self._make_page(
            "Keys",
            "Generate your local key pair and export the public key record for others to use.",
        )

        status_group = self._group("Local key status")
        status_layout = QVBoxLayout(status_group)
        self.key_status_label = QLabel()
        self.key_status_label.setWordWrap(True)
        self.data_location_label = QLabel(f"Data location:\n{get_data_paths()['data_dir']}")
        self.data_location_label.setObjectName("helper")
        self.data_location_label.setWordWrap(True)
        status_layout.addWidget(self.key_status_label)
        status_layout.addWidget(self.data_location_label)
        layout.addWidget(status_group)

        form_group = self._group("Generate key")
        form_layout = QFormLayout(form_group)
        form_layout.setLabelAlignment(Qt.AlignRight)
        self.display_name_input = QLineEdit()
        self.email_input = QLineEdit()
        self.key_passphrase_input = QLineEdit()
        self.key_passphrase_input.setEchoMode(QLineEdit.Password)
        self.key_confirm_input = QLineEdit()
        self.key_confirm_input.setEchoMode(QLineEdit.Password)
        self.key_passphrase_input.setToolTip("Stored only long enough to encrypt the local private key.")
        self.key_confirm_input.setToolTip("Must match the passphrase field.")
        form_layout.addRow("Display name", self.display_name_input)
        form_layout.addRow("Email", self.email_input)
        form_layout.addRow("Passphrase", self.key_passphrase_input)
        form_layout.addRow("Confirm passphrase", self.key_confirm_input)
        layout.addWidget(form_group)

        buttons = QHBoxLayout()
        generate_button = QPushButton("Generate Key")
        generate_button.setObjectName("primaryButton")
        generate_button.clicked.connect(self.generate_key)
        export_button = QPushButton("Export Public Key")
        export_button.clicked.connect(self.export_public_key)
        export_qr_button = QPushButton("Save Public Key QR")
        export_qr_button.clicked.connect(self.export_public_key_qr)
        export_button.setToolTip("Exports only the public key record.")
        export_qr_button.setToolTip("Saves a PNG containing only the public key record.")
        buttons.addWidget(generate_button)
        buttons.addWidget(export_button)
        buttons.addWidget(export_qr_button)
        buttons.addStretch()
        layout.addLayout(buttons)
        layout.addStretch()
        return tab

    def _build_contacts_tab(self) -> QWidget:
        tab, layout = self._make_page(
            "Contacts",
            "Import public keys, verify fingerprints through another channel, and track trust status.",
        )

        buttons = QHBoxLayout()
        import_button = QPushButton("Import Contact")
        import_button.setObjectName("primaryButton")
        import_button.clicked.connect(self.import_contact)
        verify_button = QPushButton("Verify Contact")
        verify_button.clicked.connect(self.verify_selected_contact)
        buttons.addWidget(import_button)
        buttons.addWidget(verify_button)
        buttons.addStretch()
        layout.addLayout(buttons)

        self.contacts_table = QTableWidget(0, 4)
        self.contacts_table.setHorizontalHeaderLabels(["Display name", "Email", "Fingerprint", "Status"])
        self._set_table_defaults(self.contacts_table)
        layout.addWidget(self.contacts_table, 1)
        return tab

    def _build_encrypt_tab(self) -> QWidget:
        tab, layout = self._make_page(
            "Encrypt File",
            "Choose a file and recipient. EFE writes an encrypted .efe file without overwriting existing output.",
        )

        picker_group = self._group("Input")
        picker_layout = QGridLayout(picker_group)
        self.encrypt_file_label = QLabel("No file selected")
        self.encrypt_file_label.setObjectName("pathLabel")
        self.encrypt_file_label.setWordWrap(True)
        pick_button = QPushButton("Choose File")
        pick_button.clicked.connect(self.choose_encrypt_file)
        picker_layout.addWidget(QLabel("File"), 0, 0)
        picker_layout.addWidget(self.encrypt_file_label, 0, 1)
        picker_layout.addWidget(pick_button, 0, 2)
        layout.addWidget(picker_group)

        recipient_group = self._group("Recipient")
        recipient_layout = QVBoxLayout(recipient_group)
        self.contact_combo = QComboBox()
        self.contact_combo.currentIndexChanged.connect(self.update_selected_contact_details)
        self.selected_contact_label = QLabel("No contact selected")
        self.selected_contact_label.setWordWrap(True)
        self.selected_contact_label.setObjectName("helper")
        self.unverified_warning_label = QLabel()
        self.unverified_warning_label.setWordWrap(True)
        self.unverified_warning_label.setObjectName("warningText")
        recipient_layout.addWidget(self.contact_combo)
        recipient_layout.addWidget(self.selected_contact_label)
        recipient_layout.addWidget(self.unverified_warning_label)
        layout.addWidget(recipient_group)

        encrypt_button = QPushButton("Encrypt File")
        encrypt_button.setObjectName("primaryButton")
        encrypt_button.clicked.connect(self.encrypt_selected_file)
        layout.addWidget(encrypt_button, 0, Qt.AlignLeft)
        self.encrypt_result_label = QLabel()
        self.encrypt_result_label.setWordWrap(True)
        self.encrypt_result_label.setObjectName("successText")
        layout.addWidget(self.encrypt_result_label)
        layout.addStretch()
        return tab

    def _build_decrypt_tab(self) -> QWidget:
        tab, layout = self._make_page(
            "Decrypt File",
            "Choose a .efe file and unlock your local private key with its passphrase.",
        )

        picker_group = self._group("Input")
        picker_layout = QGridLayout(picker_group)
        self.decrypt_file_label = QLabel("No .efe file selected")
        self.decrypt_file_label.setObjectName("pathLabel")
        self.decrypt_file_label.setWordWrap(True)
        pick_button = QPushButton("Choose .efe File")
        pick_button.clicked.connect(self.choose_decrypt_file)
        picker_layout.addWidget(QLabel("Encrypted file"), 0, 0)
        picker_layout.addWidget(self.decrypt_file_label, 0, 1)
        picker_layout.addWidget(pick_button, 0, 2)
        layout.addWidget(picker_group)

        form_group = self._group("Private key unlock")
        form = QFormLayout(form_group)
        self.decrypt_passphrase_input = QLineEdit()
        self.decrypt_passphrase_input.setEchoMode(QLineEdit.Password)
        self.decrypt_passphrase_input.setToolTip("Passphrase is not stored or logged.")
        form.addRow("Private key passphrase", self.decrypt_passphrase_input)
        layout.addWidget(form_group)

        decrypt_button = QPushButton("Decrypt File")
        decrypt_button.setObjectName("primaryButton")
        decrypt_button.clicked.connect(self.decrypt_selected_file)
        layout.addWidget(decrypt_button, 0, Qt.AlignLeft)
        self.decrypt_result_label = QLabel()
        self.decrypt_result_label.setWordWrap(True)
        self.decrypt_result_label.setObjectName("successText")
        layout.addWidget(self.decrypt_result_label)
        layout.addStretch()
        return tab

    def _build_audit_tab(self) -> QWidget:
        tab, layout = self._make_page(
            "Audit Log",
            "Review recent local encryption and decryption attempts. Audit entries store metadata, not file contents.",
        )
        refresh_button = QPushButton("Refresh")
        refresh_button.clicked.connect(self.refresh_audit_log)
        layout.addWidget(refresh_button, 0, Qt.AlignLeft)

        self.audit_table = QTableWidget(0, 5)
        self.audit_table.setHorizontalHeaderLabels(["Time", "Action", "File", "Recipient", "Status"])
        self._set_table_defaults(self.audit_table)
        layout.addWidget(self.audit_table, 1)
        return tab

    def refresh_all(self) -> None:
        self.refresh_key_status()
        self.refresh_contacts()
        self.refresh_audit_log()

    def refresh_key_status(self) -> None:
        if PRIVATE_KEY_PATH.exists():
            self.key_status_label.setText(f"Local private key found:\n{PRIVATE_KEY_PATH}")
            self.key_status_label.setObjectName("successText")
        else:
            self.key_status_label.setText("No local private key found. Generate a key before decrypting files.")
            self.key_status_label.setObjectName("warningText")
        self.key_status_label.style().unpolish(self.key_status_label)
        self.key_status_label.style().polish(self.key_status_label)

    def refresh_contacts(self) -> None:
        self.contacts = get_all_contacts(DB_PATH)
        self.contacts_table.setRowCount(len(self.contacts))
        self.contact_combo.blockSignals(True)
        self.contact_combo.clear()
        for row, contact in enumerate(self.contacts):
            status = "Verified" if contact["verified"] else "Unverified"
            values = [
                contact["display_name"],
                contact["email"],
                _short_fingerprint(contact["key_fingerprint"]),
                status,
            ]
            for col, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                item.setFlags(item.flags() & ~Qt.ItemIsEditable)
                if col == 3:
                    item.setToolTip("Fingerprint checked" if contact["verified"] else "Verify fingerprint before trusting")
                if col == 2:
                    item.setToolTip(contact["key_fingerprint"])
                self.contacts_table.setItem(row, col, item)
            self.contact_combo.addItem(f"{contact['display_name']} <{contact['email']}>", contact["email"])
        self.contact_combo.blockSignals(False)
        self.update_selected_contact_details()

    def refresh_audit_log(self) -> None:
        entries = get_audit_entries(DB_PATH)
        self.audit_table.setRowCount(len(entries))
        for row, entry in enumerate(entries):
            status = "Success" if entry["success"] else "Failure"
            recipient = entry["recipient_email"] or ""
            values = [
                entry["timestamp"],
                entry["action_type"],
                entry["filename"],
                recipient,
                status,
            ]
            for col, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                item.setFlags(item.flags() & ~Qt.ItemIsEditable)
                if col == 4 and not entry["success"]:
                    item.setToolTip(entry.get("error_message") or "Operation failed")
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
        status = "Verified" if contact["verified"] else "Unverified"
        self.selected_contact_label.setText(
            f"Fingerprint: {contact['key_fingerprint']}\nStatus: {status}"
        )
        if contact["verified"]:
            self.unverified_warning_label.setText("")
        else:
            self.unverified_warning_label.setText("Warning: verify this fingerprint before trusting the contact key.")
        self.update_encrypt_preflight_preview()

    def generate_key(self) -> None:
        display_name = self.display_name_input.text().strip()
        email = self.email_input.text().strip()
        passphrase = self.key_passphrase_input.text()
        confirmation = self.key_confirm_input.text()
        if not display_name:
            self.show_error("Display name is required.")
            return
        if not email:
            self.show_error("Email is required.")
            return
        if not passphrase:
            self.show_error("Passphrase cannot be empty.")
            return
        if passphrase != confirmation:
            self.show_error("Passphrases do not match.")
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
            self.show_info(
                "Public key exported",
                "Public keys may be shared, but recipients should verify the fingerprint before trusting them.\n\n"
                f"Saved to:\n{exported_path}",
            )
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
                "It does not contain your private key or passphrase.\n"
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
            self.encrypt_result_label.setText("")
            self.update_encrypt_preflight_preview()

    def choose_decrypt_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Choose .efe File", "", "EFE files (*.efe);;All files (*)")
        if path:
            self.decrypt_input_path = Path(path)
            self.decrypt_file_label.setText(str(self.decrypt_input_path))
            self.decrypt_result_label.setText("")

    def update_encrypt_preflight_preview(self) -> None:
        contact = self.selected_contact()
        if not self.encrypt_input_path or not contact:
            return
        try:
            preflight = encryption_preflight(self.encrypt_input_path, contact["email"], db_path=DB_PATH)
            status = "Verified" if preflight["recipient_verified"] else "Unverified"
            self.selected_contact_label.setText(
                f"Fingerprint: {preflight['recipient_key_fingerprint']}\n"
                f"Status: {status}\n"
                f"Output: {preflight['output_path']}"
            )
        except Exception as exc:
            self.encrypt_result_label.setText(user_error_message(exc))

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
            self.encrypt_result_label.setText(f"Encrypted file written to:\n{result['output_path']}")
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
            self.decrypt_result_label.setText(f"Decrypted file written to:\n{result['output_path']}")
            self.decrypt_passphrase_input.clear()
            self.refresh_audit_log()
        except Exception as exc:
            self.show_error(user_error_message(exc))

    def show_error(self, message: str) -> None:
        safe_message = message or "Something went wrong. Try again or check the console for details."
        self.statusBar().showMessage(safe_message)
        QMessageBox.critical(self, "EFE", safe_message)

    def show_info(self, title: str, message: str) -> None:
        self.statusBar().showMessage(message.splitlines()[0] if message else title)
        QMessageBox.information(self, title, message)
