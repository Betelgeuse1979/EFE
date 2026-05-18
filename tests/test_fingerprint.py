import unittest

from app.crypto.fingerprint import calculate_fingerprint


class FingerprintTests(unittest.TestCase):
    def test_fingerprint_is_stable_and_readable(self):
        first = calculate_fingerprint("example-public-key")
        second = calculate_fingerprint("example-public-key")

        self.assertEqual(first, second)
        self.assertIn(":", first)
        self.assertEqual(first, first.upper())


if __name__ == "__main__":
    unittest.main()
