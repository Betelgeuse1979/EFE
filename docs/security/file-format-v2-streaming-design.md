# EFE v2 Streaming Binary File Format Design

This document describes the intended v2 streaming design and the current experimental implementation. v2 support exists internally for testing, but v1 JSON/Base64 remains the default public CLI and GUI format.

The current default EFE MVP format is a JSON/Base64 `.efe` package. It now encrypts sensitive metadata such as the original filename and original file size, but encryption and decryption still read whole payloads into memory. The v2 format is a streaming binary format intended to support large files safely after more review and adversarial testing.

## Design Goals

- Stream encryption and decryption without loading full plaintext or ciphertext into memory.
- Keep sensitive metadata encrypted, including original filename and original file size unless a future technical requirement justifies exposing size.
- Keep public metadata limited to non-sensitive technical fields needed before decryption.
- Authenticate every encrypted chunk.
- Make nonce reuse impossible under the same file key.
- Fail closed on tampering, truncation, corruption, wrong key, or wrong passphrase.
- Avoid leaving partially decrypted output that looks valid.
- Preserve support for legacy v1 MVP files during migration.

## Non-Goals

- This design does not add cloud sync, public key servers, or email-client integration.
- This design does not define an installer or deployment format.
- This design does not implement multi-recipient encryption yet, but leaves room for it.

## High-Level Layout

Implemented experimental file layout:

```text
magic bytes
format version
public header length
public header bytes
encrypted metadata length
encrypted metadata bytes
chunk records...
footer record
```

All integers use fixed-width big-endian fields in the experimental implementation.

## Magic Bytes

Proposed magic:

```text
EFE2
```

The first bytes should identify the file as an EFE v2 binary package. This is public and not sensitive.

## Format Version

The binary format includes explicit version bytes after the magic bytes:

```text
major = 2
minor = 0
```

Readers reject unsupported major versions and may support compatible minor versions later if documented.

## Public Header

The public header is not encrypted. It is authenticated through AEAD associated data and/or a final integrity record.

Allowed public header fields:

- format identifier and version
- algorithm identifiers
- KDF identifiers
- key exchange mode
- recipient key fingerprint or recipient key identifier if required for recipient selection
- ephemeral public key
- metadata encryption nonce
- chunk size
- chunk nonce strategy identifier
- optional reserved flags

The public header must not contain:

- original filename
- original file size unless a future technical decision explicitly requires it
- user names
- client names
- document titles
- business context
- plaintext notes
- email subject or message content

## Encrypted Metadata Block

Sensitive file metadata should be stored in an encrypted metadata block before chunk records.

Encrypted metadata should include:

- metadata version
- original filename
- original file size
- optional MIME/content type if EFE later records it
- creation time if needed
- future extension fields

The encrypted metadata block should be encrypted and authenticated with AEAD. The public header bytes should be associated data for metadata encryption so header tampering is detected.

If metadata authentication fails, decryption must stop before writing final plaintext output.

## Chunked Ciphertext Layout

File contents should be split into fixed-size chunks. Each chunk record should contain:

- chunk index
- plaintext length for this chunk
- ciphertext length
- ciphertext bytes including AEAD tag

The chunk index and lengths are public structural data, but they must be authenticated. Either include them in the per-chunk associated data or cover them in a final manifest/integrity record.

## Default Chunk Size

Implemented default chunk size:

```text
1 MiB
```

Reasoning:

- small enough to keep memory use predictable
- large enough to avoid excessive per-chunk overhead for normal SME files
- simple to tune later if benchmarks show a better tradeoff

A 64 KiB chunk size is also defensible for very memory-constrained environments, but it increases overhead and chunk count. The implementation should keep chunk size explicit in the public header and reject unreasonable values.

## Per-Chunk Nonce Strategy

ChaCha20-Poly1305 uses a 12-byte nonce. Nonce reuse under the same key must be impossible.

Implemented strategy:

- Use the ephemeral public key with an `EFE2` context as HKDF salt.
- Derive separate keys for metadata encryption, chunk encryption, and final integrity from the X25519 shared secret using HKDF-SHA256.
- Store a random 4-byte file nonce prefix in the public header.
- Construct each chunk nonce as:

```text
4-byte random file nonce prefix || 8-byte big-endian chunk index
```

This allows up to `2^64 - 1` chunks for a single file key while avoiding random nonce collision risk per chunk.

The implementation must reject chunk indexes that overflow the nonce space.

## AEAD Authentication Per Chunk

Each chunk should be encrypted with ChaCha20-Poly1305.

Per-chunk associated data includes:

- public header hash
- chunk index
- plaintext length
- final-chunk flag

If any chunk ciphertext, tag, index, length, or associated public data is modified, that chunk must fail authentication.

## Final Chunk Handling

The final chunk may be shorter than the configured chunk size. It should be marked explicitly as final in authenticated associated data.

Zero-byte files should be represented with encrypted metadata and either:

- zero content chunks plus a final integrity record, or
- one final zero-length encrypted chunk

The simpler implementation should be chosen and tested.

## Total File Integrity Strategy

Per-chunk authentication detects corruption at the chunk level, but it does not by itself prove that the full file is complete unless finalization is authenticated.

The experimental implementation includes a final encrypted/authenticated footer containing:

- total plaintext size
- total chunk count
- hash of public header bytes
- hash of chunk record headers and ciphertext

Decryption must reject files with:

- missing footer
- wrong chunk count
- truncated final chunk
- extra unauthenticated data after footer
- chunks after the final marker

## Recipient And Key Exchange Fields

Initial v2 can keep the current one-recipient model:

- recipient static X25519 public key lives in the contact book
- sender generates an ephemeral X25519 key per file
- public header stores ephemeral public key
- file keys are derived with HKDF-SHA256

Public header may include recipient key fingerprint to help select the right private key or contact, but it should not include business-sensitive recipient context.

## Future Multi-Recipient Support

The v2 layout should reserve a path for future multi-recipient support, for example a recipient stanza list.

Each recipient stanza might later include:

- recipient key identifier/fingerprint
- ephemeral public key or wrapped content key material
- algorithm identifiers

This should not be implemented until the one-recipient streaming design is stable and reviewed.

## Backward Compatibility With v1

Decryption should continue detecting and supporting v1 MVP JSON packages where practical.

Reader behavior:

- If magic bytes are `EFE2`, parse as v2 binary.
- If the file begins as JSON and contains v1 fields, parse as legacy v1.
- If neither v2 nor supported v1 is recognized, fail with a clear unsupported-format error.

New user-facing encryption still writes v1 by default. v2 is available through an internal service/test option until more adversarial testing is complete.

## Migration And Upgrade Behavior

Migration should be explicit, not silent.

Possible future commands:

```powershell
python -m app.main inspect-file file.efe
python -m app.main rewrap-file-v2 old.efe --output new.efe
```

Migration must not require uploading files or keys to any cloud service.

## Maximum Supported Sizes

The format should define maximums before implementation:

- maximum chunk size
- maximum metadata size
- maximum chunk count
- maximum total plaintext size

Suggested initial limits:

- default chunk size: 1 MiB
- maximum chunk size: 16 MiB
- maximum encrypted metadata size: 1 MiB
- maximum chunk count: implementation-defined but below nonce overflow

If v2 streaming is not promoted before v1 public release, README and file format docs must state that v2 remains experimental and should not be treated as the default stable format.

## Failure Behavior

Decryption must fail closed for:

- corrupted public header
- unsupported version
- invalid key exchange fields
- wrong private key
- wrong passphrase
- corrupted encrypted metadata
- corrupted chunk
- missing chunk
- reordered chunk
- duplicated chunk
- truncated final chunk
- missing footer/finalization marker
- extra unauthenticated trailing bytes

Failure must not produce a final plaintext file.

## Temporary File Handling During Decrypt

Decrypt should write to a temporary file in the destination directory.

Rules:

- temporary filename should clearly indicate incomplete output
- final output path should be atomically replaced only after full authentication succeeds
- if decryption fails, the temporary file should be deleted where practical
- if deletion fails, the temporary file should remain clearly marked incomplete
- final output should not silently overwrite existing files

## Crash And Interruption Behavior

Interrupted encryption:

- should not leave a valid-looking `.efe` file
- should leave no output or an obviously incomplete temporary file

Interrupted decryption:

- should not leave a valid-looking plaintext output
- should leave no output or an obviously incomplete temporary file

The final output rename must happen only after all chunks and the final integrity record are verified.

## Public Metadata Versus Encrypted Metadata

Public metadata may reveal:

- that the file is an EFE encrypted package
- format version
- algorithm family
- recipient key fingerprint or key identifier
- chunk size
- approximate ciphertext size

Public metadata must not reveal:

- original filename
- original file size unless explicitly justified
- document title
- client or employee names
- business context
- free-form notes

Encrypted metadata should hold sensitive file information needed after decryption.

## Implementation Notes For Later

Implementation exists experimentally and should continue to be reviewed before public default use.

Suggested next order:

1. Add more binary parser/writer fixtures.
2. Add direct chunk nonce derivation tests.
3. Add crash/interruption tests for streaming encrypt and decrypt.
4. Add more corrupted/truncated/reordered chunk tests.
5. Add larger memory-use tests outside the normal unit suite.
6. Add cross-platform package compatibility fixtures.
