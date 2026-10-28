<!-- SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Test Vectors

Known-answer values produced by the shipped functions in `vauchi-core`
and verified by its test suite on every pipeline
(`vauchi-core/tests/it/protocol_test_vectors_tests.rs`). The canonical
file lives in Core at
`vauchi-core/tests/fixtures/test-vectors/vauchi-protocol-vectors-v1.json`;
CI fails this book when the copy below differs (ADR-076, decision 5:
Core stays canonical until Core verifies against a pinned spec tag).

The file is self-describing: its `description` entries state each
derivation. Conventions: lower-case hex, HKDF-SHA256 with an absent
salt meaning 32 zero bytes, X25519 and Ed25519, XChaCha20-Poly1305 in
the tagged format. The plain-language walk-through is at
[vauchi.app/docs](https://vauchi.app/docs/developers/test-vectors.html).

Entries: `identity` (Keys and Cards A2, A3), `x3dh` (the two-DH
agreement of the relay-mediated exchange), `ratchet` (one Double
Ratchet step and one message), `mailbox_tokens` (the three daily
tokens), `backup` (a legacy v3 file and its key) and `backup_v6` (the
file the app writes today: the authenticated `0x06 || salt` header,
the Argon2id base key, the `vauchi-backup-v6-state` key and a complete
file). The v6 entry is produced with the production Argon2id
parameters; the test that imports it through the app's own function
runs only in builds that carry them
(`backup_v6_vector_imports_with_production_argon2id_and_refuses_a_wrong_password`),
while the test that opens it from the recorded base key and checks
that a changed header fails the tag runs in every build
(`backup_v6_vector_decrypts_under_its_header_and_not_under_a_changed_one`).

Not yet covered, and the natural next additions: the symmetric QR
exchange key and its confirmation tokens; the link exchange's gate,
slot and escrow keys; the relay-mediated short code and its SAS; the
BLE handshake and advertisement tokens; device-link confirmation codes;
social-recovery shares; and full protocol transcripts with
intermediate values.

Download: [vauchi-protocol-vectors-v1.json](vectors/vauchi-protocol-vectors-v1.json)

```json
{{#include vectors/vauchi-protocol-vectors-v1.json}}
```
