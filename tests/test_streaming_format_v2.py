import os
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.crypto.decrypt import decrypt_file
from app.crypto.encrypt import encrypt_file_for_contact
from app.crypto.file_format import V2_MAGIC
from app.crypto.key_manager import generate_user_key_pair
from app.crypto.streaming_encrypt import encrypt_file_for_contact_streaming
from app.exceptions import InvalidEfeFileError, PrivateKeyUnlockError
from app.services.file_crypto_service import encrypt_file_for_recipient
from app.services.contact_service import import_contact_key
from app.services.key_service import initialize_user_key


class StreamingFormatV2Tests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.private_key_path = self.root / "private.pem"
        self.public_key_path = self.root / "public.json"
        self.passphrase = b"streaming v2 passphrase"
        self.contact = generate_user_key_pair(
            "Bob Example",
            "bob@example.com",
            passphrase=self.passphrase,
            private_key_path=self.private_key_path,
            public_key_record_path=self.public_key_path,
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def _make_v2_file(self, name="message.txt", content=b"hello from v2", chunk_size=64):
        source = self.root / name
        encrypted = self.root / "attachment.efe"
        decrypted = self.root / "decrypted.txt"
        source.write_bytes(content)
        encrypt_file_for_contact_streaming(source, self.contact, encrypted, chunk_size=chunk_size)
        return source, encrypted, decrypted

    def _read_mutable(self, path: Path) -> bytearray:
        return bytearray(path.read_bytes())

    def _write_mutable(self, path: Path, data: bytearray) -> None:
        path.write_bytes(bytes(data))

    def _offsets(self, path: Path) -> dict:
        data = path.read_bytes()
        header_length = struct.unpack(">I", data[6:10])[0]
        header_start = 10
        header_end = header_start + header_length
        metadata_length_offset = header_end
        metadata_length = struct.unpack(">I", data[metadata_length_offset : metadata_length_offset + 4])[0]
        metadata_start = metadata_length_offset + 4
        metadata_end = metadata_start + metadata_length
        cursor = metadata_end
        first_chunk_start = None
        first_chunk_ciphertext_start = None
        footer_start = None
        while cursor < len(data):
            record_type = data[cursor : cursor + 1]
            if record_type == b"C":
                if first_chunk_start is None:
                    first_chunk_start = cursor
                    first_chunk_ciphertext_start = cursor + 18
                ciphertext_length = struct.unpack(">I", data[cursor + 14 : cursor + 18])[0]
                cursor += 18 + ciphertext_length
            elif record_type == b"F":
                footer_start = cursor
                break
            else:
                break
        return {
            "header_start": header_start,
            "header_end": header_end,
            "metadata_start": metadata_start,
            "metadata_end": metadata_end,
            "first_chunk_start": first_chunk_start,
            "first_chunk_ciphertext_start": first_chunk_ciphertext_start,
            "footer_start": footer_start,
            "data_length": len(data),
        }

    def test_v2_encrypt_decrypt_roundtrip_and_magic(self):
        source, encrypted, decrypted = self._make_v2_file(content=b"hello from streaming v2")

        result = decrypt_file(encrypted, decrypted, private_key_path=self.private_key_path, passphrase=self.passphrase)

        self.assertEqual(result, decrypted)
        self.assertEqual(decrypted.read_bytes(), source.read_bytes())
        self.assertEqual(encrypted.read_bytes()[:4], V2_MAGIC)

    def test_v2_filename_and_metadata_fields_are_not_plaintext(self):
        sensitive_name = "Retrenchment_List_2026.txt"
        source, encrypted, decrypted = self._make_v2_file(name=sensitive_name, content=b"payroll-private-data")

        encrypted_bytes = encrypted.read_bytes()
        self.assertNotIn(sensitive_name.encode("utf-8"), encrypted_bytes)
        self.assertNotIn(b"original_filename", encrypted_bytes)
        self.assertNotIn(b"original_size", encrypted_bytes)
        with patch("app.crypto.streaming_decrypt.DECRYPTED_DIR", self.root / "default-decrypted"):
            decrypted_path = decrypt_file(encrypted, private_key_path=self.private_key_path, passphrase=self.passphrase)

        self.assertEqual(decrypted_path.name, sensitive_name)
        self.assertEqual(decrypted_path.read_bytes(), source.read_bytes())
        self.assertFalse(decrypted.exists())

    def test_v2_unicode_filename_roundtrip(self):
        source, encrypted, _ = self._make_v2_file(name="résumé_客户.txt", content="unicode content".encode("utf-8"))

        with patch("app.crypto.streaming_decrypt.DECRYPTED_DIR", self.root / "unicode-out"):
            decrypted_path = decrypt_file(encrypted, private_key_path=self.private_key_path, passphrase=self.passphrase)

        self.assertEqual(decrypted_path.name, source.name)
        self.assertEqual(decrypted_path.read_bytes(), source.read_bytes())

    def test_v2_long_filename_is_bounded_safely(self):
        long_name = f"{'a' * 240}.txt"
        source, encrypted, _ = self._make_v2_file(name=long_name, content=b"long filename")

        with patch("app.crypto.streaming_decrypt.DECRYPTED_DIR", self.root / "long-out"):
            decrypted_path = decrypt_file(encrypted, private_key_path=self.private_key_path, passphrase=self.passphrase)

        self.assertLessEqual(len(decrypted_path.name), 180)
        self.assertEqual(decrypted_path.suffix, ".txt")
        self.assertEqual(decrypted_path.read_bytes(), source.read_bytes())

    def test_v2_zero_byte_file_roundtrip(self):
        source, encrypted, decrypted = self._make_v2_file(content=b"")

        decrypt_file(encrypted, decrypted, private_key_path=self.private_key_path, passphrase=self.passphrase)

        self.assertEqual(decrypted.read_bytes(), source.read_bytes())

    def test_v2_large_file_uses_multiple_chunks_and_roundtrips(self):
        content = os.urandom(1024 * 1024 + 777)
        source, encrypted, decrypted = self._make_v2_file(content=content, chunk_size=64 * 1024)
        chunk_records = encrypted.read_bytes().count(b"C")

        decrypt_file(encrypted, decrypted, private_key_path=self.private_key_path, passphrase=self.passphrase)

        self.assertGreaterEqual(chunk_records, 2)
        self.assertEqual(decrypted.read_bytes(), source.read_bytes())

    def test_v2_wrong_private_key_fails_without_plaintext(self):
        _, encrypted, decrypted = self._make_v2_file()
        wrong_private = self.root / "wrong-private.pem"
        wrong_public = self.root / "wrong-public.json"
        wrong_passphrase = b"wrong recipient passphrase"
        generate_user_key_pair(
            "Mallory Example",
            "mallory@example.com",
            passphrase=wrong_passphrase,
            private_key_path=wrong_private,
            public_key_record_path=wrong_public,
        )

        with self.assertRaises(InvalidEfeFileError):
            decrypt_file(encrypted, decrypted, private_key_path=wrong_private, passphrase=wrong_passphrase)

        self.assertFalse(decrypted.exists())

    def test_v2_wrong_passphrase_fails_without_plaintext(self):
        _, encrypted, decrypted = self._make_v2_file()

        with self.assertRaises(PrivateKeyUnlockError):
            decrypt_file(encrypted, decrypted, private_key_path=self.private_key_path, passphrase=b"wrong")

        self.assertFalse(decrypted.exists())

    def test_v2_corrupted_public_header_fails(self):
        _, encrypted, decrypted = self._make_v2_file()
        data = self._read_mutable(encrypted)
        offsets = self._offsets(encrypted)
        data[offsets["header_start"] + 5] ^= 1
        self._write_mutable(encrypted, data)

        with self.assertRaises(InvalidEfeFileError):
            decrypt_file(encrypted, decrypted, private_key_path=self.private_key_path, passphrase=self.passphrase)

        self.assertFalse(decrypted.exists())

    def test_v2_corrupted_encrypted_metadata_fails(self):
        _, encrypted, decrypted = self._make_v2_file()
        data = self._read_mutable(encrypted)
        offsets = self._offsets(encrypted)
        data[offsets["metadata_start"]] ^= 1
        self._write_mutable(encrypted, data)

        with self.assertRaises(InvalidEfeFileError):
            decrypt_file(encrypted, decrypted, private_key_path=self.private_key_path, passphrase=self.passphrase)

        self.assertFalse(decrypted.exists())

    def test_v2_corrupted_chunk_fails_and_cleans_temp_output(self):
        _, encrypted, decrypted = self._make_v2_file(content=b"abc" * 100)
        data = self._read_mutable(encrypted)
        offsets = self._offsets(encrypted)
        data[offsets["first_chunk_ciphertext_start"]] ^= 1
        self._write_mutable(encrypted, data)

        with self.assertRaises(InvalidEfeFileError):
            decrypt_file(encrypted, decrypted, private_key_path=self.private_key_path, passphrase=self.passphrase)

        self.assertFalse(decrypted.exists())
        self.assertEqual(list(self.root.glob("*.incomplete")), [])

    def test_v2_missing_chunk_fails(self):
        _, encrypted, decrypted = self._make_v2_file(content=b"abc" * 100, chunk_size=64)
        data = self._read_mutable(encrypted)
        offsets = self._offsets(encrypted)
        first_chunk_start = offsets["first_chunk_start"]
        first_chunk_ciphertext_length = struct.unpack(">I", data[first_chunk_start + 14 : first_chunk_start + 18])[0]
        del data[first_chunk_start : first_chunk_start + 18 + first_chunk_ciphertext_length]
        self._write_mutable(encrypted, data)

        with self.assertRaises(InvalidEfeFileError):
            decrypt_file(encrypted, decrypted, private_key_path=self.private_key_path, passphrase=self.passphrase)

        self.assertFalse(decrypted.exists())

    def test_v2_truncated_final_chunk_fails(self):
        _, encrypted, decrypted = self._make_v2_file(content=b"abc" * 100, chunk_size=64)
        data = self._read_mutable(encrypted)
        offsets = self._offsets(encrypted)
        del data[offsets["footer_start"] - 5 : offsets["footer_start"]]
        self._write_mutable(encrypted, data)

        with self.assertRaises(InvalidEfeFileError):
            decrypt_file(encrypted, decrypted, private_key_path=self.private_key_path, passphrase=self.passphrase)

        self.assertFalse(decrypted.exists())

    def test_v2_tampered_footer_manifest_fails(self):
        _, encrypted, decrypted = self._make_v2_file(content=b"abc" * 100)
        data = self._read_mutable(encrypted)
        offsets = self._offsets(encrypted)
        footer_ciphertext_start = offsets["footer_start"] + 5
        data[footer_ciphertext_start] ^= 1
        self._write_mutable(encrypted, data)

        with self.assertRaises(InvalidEfeFileError):
            decrypt_file(encrypted, decrypted, private_key_path=self.private_key_path, passphrase=self.passphrase)

        self.assertFalse(decrypted.exists())

    def test_v2_extra_trailing_data_fails(self):
        _, encrypted, decrypted = self._make_v2_file(content=b"abc" * 100)
        with encrypted.open("ab") as output_file:
            output_file.write(b"extra")

        with self.assertRaises(InvalidEfeFileError):
            decrypt_file(encrypted, decrypted, private_key_path=self.private_key_path, passphrase=self.passphrase)

        self.assertFalse(decrypted.exists())

    def test_service_layer_can_select_v2_without_changing_default(self):
        db_path = self.root / "efe.db"
        user_private = self.root / "service-private.pem"
        user_public = self.root / "service-public.json"
        initialize_user_key(
            "Service User",
            "service@example.com",
            passphrase=self.passphrase,
            private_key_path=user_private,
            public_key_record_path=user_public,
        )
        import_contact_key(user_public, verified=True, db_path=db_path)
        source = self.root / "service.txt"
        v1_output = self.root / "service-v1.efe"
        v2_output = self.root / "service-v2.efe"
        source.write_text("service data", encoding="utf-8")

        v1_result = encrypt_file_for_recipient(source, "service@example.com", v1_output, db_path=db_path)
        v2_result = encrypt_file_for_recipient(
            source,
            "service@example.com",
            v2_output,
            db_path=db_path,
            format_version="v2",
        )

        self.assertNotEqual(Path(v1_result["output_path"]).read_bytes()[:4], V2_MAGIC)
        self.assertEqual(Path(v2_result["output_path"]).read_bytes()[:4], V2_MAGIC)
        self.assertEqual(v1_result["format_version"], "v1")
        self.assertEqual(v2_result["format_version"], "v2")

    def test_legacy_v1_decrypt_still_works_with_auto_detection(self):
        source = self.root / "legacy.txt"
        encrypted = self.root / "legacy.efe"
        decrypted = self.root / "legacy.out"
        source.write_text("legacy content", encoding="utf-8")
        encrypt_file_for_contact(source, self.contact, encrypted)

        decrypt_file(encrypted, decrypted, private_key_path=self.private_key_path, passphrase=self.passphrase)

        self.assertEqual(decrypted.read_text(encoding="utf-8"), "legacy content")

    def test_unknown_file_format_fails_cleanly(self):
        encrypted = self.root / "unknown.efe"
        decrypted = self.root / "unknown.out"
        encrypted.write_bytes(b"not-json-and-not-efe2")

        with self.assertRaises(InvalidEfeFileError):
            decrypt_file(encrypted, decrypted, private_key_path=self.private_key_path, passphrase=self.passphrase)

        self.assertFalse(decrypted.exists())


if __name__ == "__main__":
    unittest.main()
