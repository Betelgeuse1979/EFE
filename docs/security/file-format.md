# EFE File Format

EFE encrypted files use the `.efe` extension. A `.efe` file is an encrypted file or attachment. It is not an email message and does not contain Outlook, Gmail, or other email client data.

The current format is JSON with a top-level public header and ciphertext.

This document reflects the v0.6 public-key QR export checkpoint. QR export uses PNG images containing public key JSON records and does not change the `.efe` encrypted file format.

## Required Top-Level Fields

- `header`
- `ciphertext`

## Required Header Fields

- `format`
- `generated_by_app`
- `app_version`
- `created_at`
- `metadata_mode`
- `recipient_email`
- `recipient_key_fingerprint`
- `ephemeral_public_key`
- `nonce`

## Base64 Fields

- `ciphertext`
- `header.ephemeral_public_key`
- `header.nonce`

## Format Marker

The current format marker is:

```text
efe-X25519-ChaCha20Poly1305-v1
```

This marker is authenticated as part of the header. Files with unsupported format markers fail decryption.

## Authenticated Header Behaviour

The public header is passed to ChaCha20-Poly1305 as associated authenticated data. Header fields are not encrypted, but they are authenticated. If any authenticated header value is changed, decryption fails.

Authenticated public header fields include technical metadata such as format, app version, recipient email, recipient key fingerprint, nonce, ephemeral public key, and metadata mode.

New `.efe` files do not store `original_filename` in the public header. Sensitive file metadata is encrypted inside the ciphertext and authenticated by ChaCha20-Poly1305.

## Encrypted Metadata

For new files, the plaintext passed to ChaCha20-Poly1305 is:

```text
4-byte big-endian metadata length || metadata JSON || file bytes
```

The encrypted metadata currently includes:

- `metadata_version`
- `original_filename`
- `original_size`

This means the original filename is only available after successful decryption/authentication. A `.efe` package may still reveal that it is an EFE encrypted file, but new files should not reveal the original document name.

## Example Structure

```json
{
  "header": {
    "format": "efe-X25519-ChaCha20Poly1305-v1",
    "generated_by_app": "efe",
    "app_version": "0.1.0",
    "created_at": "2026-05-19T12:00:00+00:00",
    "metadata_mode": "encrypted-json-v1",
    "recipient_email": "recipient@example.com",
    "recipient_key_fingerprint": "ABCD:1234:...",
    "ephemeral_public_key": "...",
    "nonce": "..."
  },
  "ciphertext": "..."
}
```

## What Causes Decrypt Failure

Decryption fails if:

- the file is not valid JSON
- a required top-level field is missing
- a required header field is missing
- a base64 field is invalid
- the format marker is unsupported
- the ephemeral public key is invalid
- the nonce is invalid
- encrypted metadata is modified
- the ciphertext is modified
- any authenticated header field is modified
- the file was encrypted for a different private key
- the private key passphrase is wrong
- the output file already exists
- the filesystem denies access

## Backwards Compatibility

EFE is still an MVP. No backwards compatibility guarantee is made yet for future `.efe` format versions.

Current files include an explicit format marker so future versions can detect and reject unsupported formats safely.

Legacy MVP files that stored `original_filename` in the public header are still supported for decryption where practical. Those files should be treated as legacy because they leak filename metadata. New files use encrypted metadata instead.

When no explicit encrypted output path is provided, EFE also writes a generic random `.efe` package filename instead of deriving the output name from the source filename.

## Future Versioning Considerations

Future formats should preserve:

- an explicit format/version marker
- authenticated metadata
- clear base64 field definitions
- safe rejection of unsupported versions
- tests for malformed, tampered, and wrong-key files

If EFE later migrates to age/pyrage or another file format, migration should be documented and tested.
