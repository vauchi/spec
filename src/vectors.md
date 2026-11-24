<!-- SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- description: Known-answer test vectors from the shipped vauchi-core functions, from identity derivation to backups and exchanges, to check an implementation against Core. -->

# Test Vectors

Known-answer values produced by the shipped functions in `vauchi-core`
and verified by its test suite: the `identity` to `backup_v6`
entries by `vauchi-core/tests/it/protocol_test_vectors_tests.rs`,
`backup_v7` by `protocol_test_vectors_backup_v7_tests.rs`, the two
exchange entries by `protocol_exchange_vectors_tests.rs`. Core's
`test:core` job runs all three files; its `test:vectors` job, which
adds production Argon2id, filters on `protocol_test_vectors` and so
runs the first two. The canonical
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
tokens), `backup` (a legacy v3 file and its key), `backup_v6` (the
file the app wrote before v7, kept as recorded: the authenticated
`0x06 || salt` header, the Argon2id base key, the
`vauchi-backup-v6-state` key and a complete file), `backup_v7` (the
file the app writes today: the authenticated `0x07 || file_id ||
salt_0 || salt_1` header, the slot the password opens, its Argon2id
base key, the `vauchi-backup-v7-payload` key and a complete file;
`backup_v7_vector_opens_its_real_payload_under_its_header_only` and
`backup_v7_vector_imports_with_production_argon2id_and_refuses_a_wrong_password`),
`qr_symmetric` and `link_exchange` (below), and `recovery_proof` (the
stored recovery proof of Social Recovery B3: fixed old, new and helper
seeds, the sealing key `HKDF(old_pk, "Vauchi_RecoveryProof_v3")`, the
plain postcard and the sealed bytes;
`recovery_proof_vector_opens_under_its_old_key_and_not_another` opens
it under the old key, by hand from the recorded key, and not under
another). The v6 entry is produced with the production Argon2id
parameters; the test that imports it through the app's own function
runs only in builds that carry them
(`backup_v6_vector_imports_with_production_argon2id_and_refuses_a_wrong_password`),
while the test that opens it from the recorded base key and checks
that a changed header fails the tag runs in every build
(`backup_v6_vector_decrypts_under_its_header_and_not_under_a_changed_one`).

Two entries cover an exchange end to end. `qr_symmetric` is the
mutual QR exchange of In-Person Exchange A4 and A5: two identities
from fixed seeds and two fixed ephemeral keys driven through the
shipped `ExchangeSession` to the key agreement, recording the DH, the
sorted-key `info`, the shared key, both reciprocity tokens and the
confirmation escrow gate and slots
(`qr_symmetric_vector_matches_the_session_and_its_formulas`).
`link_exchange` is one link exchange of Link and Relay-Mediated
Exchange A1 to A10: the link built from a fixed nonce and ephemeral
key, the three nonce-derived slots, the escrow gate, slots and card
key from the responder's DH and a fixed PAKE key, the card payload for a card with a fixed
id signed for the link's nonce and both ephemeral keys, and the shared
key the two fresh X3DH keys give
(`link_exchange_vector_matches_the_url_slots_escrow_payload_and_shared_key`,
which also opens a card sealed by `EscrowKeys` with the recorded card
key and refuses the payload with one flipped bit).

Not yet covered, and the natural next additions: the relay-mediated
short code and its authentication fingerprint; the link exchange's SPAKE2 run, whose scalar comes from the CSPRNG; the BLE handshake and advertisement tokens;
the NFC key; device-link confirmation codes; social-recovery shares
and sealed boxes; the signed OHTTP key record.

Download: [vauchi-protocol-vectors-v1.json](vectors/vauchi-protocol-vectors-v1.json)

```json
{{#include vectors/vauchi-protocol-vectors-v1.json}}
```

## Notice core (proposed)

Known-answer values and conformance schedules for the
[Notice Core](./protocols/notice-core.md), a proposed protocol
(ADR-081) that is not in the app. The canonical files live in Core
next to the protocol vectors; `check:vectors` fails this book when a
copy below differs from Core's `main`.

- `notice-core-vectors-v7.json`: one fixed set of inputs (device,
  handshake, refresh and ephemeral private keys, an update key, a week)
  and what they give: the seed epoch's keys and ID, the first notice
  chain steps, refresh and opening addresses, the proof tag, an opened
  epoch with its confirmation and key ID, the plaintexts and sealed
  bytes of an update, a refresh and an opening notice, and a body's
  commitment and content records. Checked by Core's
  `notice_key_schedule_tests.rs`, `notice_seal_tests.rs` and
  `notice_content_tests.rs`.
- `notice-schedules-v1.json`: 50 schedules of sessions for one
  direction, 3,527 sessions in all: which device acts and at what
  hour, which earlier writes the gateway delivers (so what it drops,
  delays or replays), which delivered records it alters, whether the
  write is acknowledged, and the edits.
- `notice-conformance-expected-v1.json`: what an implementation written
  from the protocol text alone, independently of Core, decided at each
  of those sessions: records written, epochs kept, updates read and
  alarms raised. Core's `notice_conformance_tests.rs` replays every
  schedule and must decide the same. The schedules use unlimited
  slots, so they do not exercise the session budget or the control
  turns.

Downloads:
[notice-core-vectors-v7.json](vectors/notice-core-vectors-v7.json),
[notice-schedules-v1.json](vectors/notice-schedules-v1.json),
[notice-conformance-expected-v1.json](vectors/notice-conformance-expected-v1.json).

```json
{{#include vectors/notice-core-vectors-v7.json}}
```
