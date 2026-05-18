import unittest

from app.main import _user_error_message


class CliErrorMessageTests(unittest.TestCase):
    def test_existing_output_error_is_user_facing(self):
        message = _user_error_message(FileExistsError("already exists"))

        self.assertEqual(message, "Output file already exists. Choose a different output path.")

    def test_missing_input_error_is_user_facing(self):
        message = _user_error_message(FileNotFoundError("missing"))

        self.assertEqual(message, "File or directory not found. Check the path and try again.")

    def test_permission_error_is_user_facing(self):
        message = _user_error_message(PermissionError("denied"))

        self.assertEqual(message, "Permission denied while accessing a file or directory. Check the path permissions.")


if __name__ == "__main__":
    unittest.main()
