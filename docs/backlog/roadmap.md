# EFE Roadmap

EFE, short for Encrypted File Exchange, is intended to remain a practical local-first encrypted file exchange tool. The basic desktop app and command-line workflow should be free for normal individual use and should act as the trust-building foundation for a wider SME security software ecosystem.

EFE should not become an email client, cloud storage product, or central public key directory. Users should be able to generate keys, exchange public keys, encrypt files, and decrypt `.efe` files without depending on cloud infrastructure.

## Product Positioning

- EFE desktop is the free entry point for encrypted file exchange.
- The `.efe` file format is the protocol layer for encrypted files and attachments.
- Core encryption and decryption must remain local-first.
- Public keys may be shared, but public key fingerprints must be verified before trust.
- EFE can support practical safeguards and evidence of reasonable steps, but it does not make an organisation automatically POPIA compliant.
- EFE remains an MVP until its file format, UX, packaging, and audit posture are ready for broader release.

## Ecosystem Direction

Future commercial or business workflow modules may be built around the free EFE foundation:

- Secure Send Register / Evidence Log for recording file exchange events and verification steps.
- POPIA practical evidence tools for documenting reasonable technical and organisational safeguards.
- Bank Statement Converter encrypted `.efe` export integration.
- Cisco Backup encrypted `.efe` storage integration.
- Team/business deployment tooling for managed rollout, templates, and support workflows.
- Support contracts and commercial services for SMEs.

These future products should reuse EFE components where sensible instead of duplicating crypto, key management, fingerprint verification, or file format handling.

## v1 File-Format Stabilization

Before a v1 public release, EFE must stabilize the `.efe` file format and document compatibility expectations.

Required v1 work:

- Freeze v1 `.efe` file format requirements.
- Keep plaintext metadata leakage fixed for new files, especially `original_filename`, and continue reviewing remaining public header fields.
- Decide whether the current JSON/Base64 format remains temporary or is replaced with a binary streaming format.
- Support explicit format versioning and backward compatibility planning.
- Add adversarial tests for malformed, tampered, truncated, and partially written `.efe` files.
- Add a large-file strategy, preferably a streaming binary format or a documented file size limit until streaming lands.
- Document what metadata is encrypted, authenticated, omitted, or intentionally visible.
- Document migration expectations if the current MVP format is replaced before v1.

## v2 Streaming Binary Format

The current MVP format is not streaming-friendly. EFE should design the `.efe` v2 streaming binary format before implementing it.

Milestone intent:

- design first, implementation later
- support large files without loading full plaintext or ciphertext into memory
- keep original filename and original file size encrypted
- authenticate every encrypted chunk
- define safe nonce derivation for chunks
- define total-file integrity and truncation detection
- keep legacy v1 decrypt support where practical

The v1 public release should either include streaming support or explicitly document conservative file size limits until streaming lands.

## Near-Term Backlog

- Review remaining `.efe` public header fields and remove avoidable plaintext metadata.
- Decide whether v1 requires streaming encryption before release.
- Review `docs/security/file-format-v2-streaming-design.md` before implementing streaming support.
- Extend failure-mode tests around corrupted package structures and file I/O interruptions.
- Continue packaging work without adding installer, code signing, or auto-update until the application behavior is stable.
- Prepare for independent security review before encouraging high-risk or regulated use.
