# EFE File Format

EFE encrypted files use the `.efe` extension. A `.efe` file is an encrypted file or attachment. It is not an email message and does not contain Outlook, Gmail, or other email client data.

The current format is JSON with a top-level header and ciphertext.

## Required Top-Level Fields

- `header`
- `ciphertext`

## Required Header Fields

- `format`
- `generated_by_app`
- `app_version`
- `created_at`
- `original_filename`
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

The header is passed to ChaCha20-Poly1305 as associated authenticated data. Header fields are not encrypted, but they are authenticated. If any authenticated header value is changed, decryption fails.

Authenticated header fields include metadata such as the original filename, recipient email, recipient key fingerprint, nonce, and ephemeral public key.

## Example Structure

```json
{
  "header": {
    "format": "efe-X25519-ChaCha20Poly1305-v1",
    "generated_by_app": "efe",
    "app_version": "0.1.0",
    "created_at": "2026-05-19T12:00:00+00:00",
    "original_filename": "document.pdf",
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
- the ciphertext is modified
- any authenticated header field is modified
- the file was encrypted for a different private key
- the private key passphrase is wrong
- the output file already exists
- the filesystem denies access

## Backwards Compatibility

EFE is still an MVP. No backwards compatibility guarantee is made yet for future `.efe` format versions.

Current files include an explicit format marker so future versions can detect and reject unsupported formats safely.

## Future Versioning Considerations

Future formats should preserve:

- an explicit format/version marker
- authenticated metadata
- clear base64 field definitions
- safe rejection of unsupported versions
- tests for malformed, tampered, and wrong-key files

If EFE later migrates to age/pyrage or another file format, migration should be documented and tested.
