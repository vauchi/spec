<!-- SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- description: How one 32-byte master seed derives the identity's keys, moves to a new device, and makes data at rest unreadable once its keys are gone; and what cards hold. -->

# Keys and Cards

> **Status: extracted 2026-10-28** from `vauchi/core` `612992b0b`;
> checked against `a9a911b0a` on 2026-10-30.
> This chapter is the data layer the protocol chapters stand on: the
> key hierarchy from one master seed (A), the primitives (B), storage
> at rest and its erasure (C), backups (D), linking a second device
> (E), the duress unlock (F), and the card with its visibility and
> trust rules (G). Claims backed: [S10](../claims.md),
> [S12](../claims.md), [S13](../claims.md), [S14](../claims.md),
> [S15](../claims.md).

## Goal

One 32-byte master seed is the whole identity: every signing, exchange,
device and storage key derives from it, so a person can carry it to a
new device in a backup or a device link and lose nothing, and can
destroy the keys in secure storage and make everything at rest
unreadable. Cards are the data this protects: what a person shares,
field by field, with each contact.

## Actors

- **Owner**: the person holding the seed on one or more devices.
- **New device**: a device the owner links to the identity (E).
- **Thief**: has the device, powered off or locked, and the file
  system; may also have a backup file.
- **Coercer**: has the owner and the unlocked device, and watches the
  network and the relay (F).
- **Contact**: receives a card and later its updates; sees what the
  visibility rules grant (G).
- **Attacker** (E): the attacker of `device_link.spthy`: owns the
  network and the relay and may photograph a screen.

---

## A. Key hierarchy

### Normative operations

Source: `vauchi-core/src/identity/mod.rs`, `identity/device.rs`,
`crypto/signing.rs`, `crypto/shredding.rs`, `crypto/kdf.rs`.

**A1. Master seed** (`Identity::create`). 32 random bytes from the
operating system's CSPRNG (`rand_core::OsRng`, `crypto::random_bytes`).
Nothing else in the identity is random: given the seed, every key
below is a function.

**A2. Identity keys** (`Identity::from_seed_with_device`).

```text
signing   = Ed25519 key pair with the seed as its secret
            (SigningKeyPair::from_seed, no derivation)
exchange  = X25519 key pair from HKDF(seed, "Vauchi_Exchange_Seed_v2")
```

The Ed25519 public key is the identity: it is what a QR shows, what a
contact stores, and what signs cards, registries and reciprocity
confirmations. The X25519 key is the identity's static exchange key
(the `x` of the Bluetooth handshake, the static key of the relay
exchange). It is not the Ed25519 key converted to Montgomery form: a
test pins that the two differ
(`exchange_seed_secret_is_not_the_guardian_recipient`). The Ed25519
key is also converted to X25519 (`to_x25519_secret`,
`crypto/signing.rs`), for one purpose: opening the sealed boxes
addressed to a guardian's signing key (ADR-002 amendment).

**A3. Device keys** (`DeviceInfo::derive`). Each device of an identity
has an index `i` (`u32`, 0 for the first device) and

```text
device_id       = HKDF(seed, "Vauchi_Device_ID_v2"       || i as LE u32)
device_exchange = X25519 from HKDF(seed, "Vauchi_Device_Exchange_v2" || i as LE u32)
```

Every device of an identity can compute every other device's keys;
the index is what distinguishes them. The per-device exchange key is
what device-to-device ratchets are keyed from
(`bootstrap_device_pair_ratchet`, info `vauchi-device-pair-ratchet-v1`).

**A4. Device registry** (`DeviceRegistry`). The list of an identity's
devices, each `(device_id, exchange_public_key, device_name,
created_at, revoked, revoked_at, last_sync_at)`, with a version
counter and an Ed25519 signature by the identity over

```text
version as LE u64 || count as LE u32
|| for each device: device_id || exchange_public_key || revoked as 1 byte
```

A registry MUST refuse an eleventh active device (`MAX_DEVICES = 10`),
a duplicate device id, and the revocation of the last active device.
Every change bumps the version; a signed change also re-signs, while
`add_device_unsigned`, used during linking, bumps it without signing
and leaves the signature to the caller. No index is stored in an
entry: the next index is the number of devices ever registered,
revoked ones included, so an index is never reused.

**A5. Storage keys** (`ShreddingMasterKey`).

```text
SMK  = HKDF(seed, "Vauchi_Shred_Key_v2")
SEK  = HKDF(SMK,  "Vauchi_Storage_Key_v2")     the database key
FKEK = HKDF(SMK,  "Vauchi_FileKey_Key_v2")     wraps file keys
```

The SMK is derived once, when the identity is created or migrated,
and stored raw in the platform's secure storage (Keychain, Secret
Service, Credential Manager). At boot it is loaded from there and
never re-derived (ADR-033): re-deriving would need the seed, which
lives in the database the SMK opens. Before an identity exists the
database is under a random bootstrap key, also in secure storage; the
move to the SEK happens once the SMK is saved
(`api/vauchi/storage_keys.rs`).

The receive state a locked phone advances is under a second key, the
background receive key (BRK, ADR-033 amendment 2026-11-07): 32 random
bytes, not derived from the SMK, whose source cannot be read while the
phone is locked. It is stored in the class of secure storage readable
after the first unlock since boot, made with the identity or at the first
open of an older one, never replaced, and destroyed by every shred with
the SMK. Ratchet states and the mailbox tokens stored ahead for yesterday,
today and tomorrow, the days an up-to-date receive registers within the next
24 hours, are sealed under keys derived from it, in the same database file
as the rest, so a received update still commits ratchet and card in one
transaction (`storage/receive_key.rs`). Each stored day carries the end of
the locked window, 24 hours after the unlocked sync that stored it; every
unlocked sync rewrites the three days, and the next unlock catches up through
the receive checkpoint (ADR-033 addendum 2026-11-09,
`api/vauchi/receive_tokens_ahead.rs`):

```text
ratchet key = HKDF(BRK, "vauchi-ratchet-receive-key-v1:" || contact id)
day key     = HKDF(BRK, "vauchi-receive-tokens-v1:" || day, 8 bytes BE)
check key   = HKDF(BRK, "Vauchi_Receive_Key_Check_v1")
```

**A6. HKDF and the salt rule.** Every derivation in this book is
HKDF-SHA256 (RFC 5869). `HKDF::derive_key(None, ikm, info)` means a
zero salt of 32 bytes; a salt is passed only where the text says so.
Every info string is unique to one purpose (ADR-007); changing an
input's meaning bumps the version in the string.

### Security considerations

- The seed is the identity. Anyone who holds it holds every key, past
  and future, on every device index; A3 means a linked device is a
  full copy, not a sub-identity (see E and [S15](../claims.md)).
  Per-device subkeys that would contain a leak are tracked work. After a
  leak the remedy is a move to the pre-committed next key (Social
  Recovery D, ADR-083, proposed), whose commitment every in-person
  exchange carries (Social Recovery D1).
- A restore from an identity backup (D1) or a full backup (D4) joins
  the identity as a new device with a random device index, so two
  installs restored from one backup are two devices to the protocol,
  each with its own signing key.

---

## B. Primitives

Source: `vauchi-core/src/crypto/encryption.rs`, `padding.rs`,
`password_kdf.rs`, `kdf.rs`.

**B1. Authenticated encryption.** XChaCha20-Poly1305 only, in a tagged
format:

```text
0x02 || nonce(24) || ciphertext || tag(16)           encrypt / decrypt
0x03 || nonce(24) || ciphertext || tag(16)           with associated data
```

The nonce is random per call from the OS CSPRNG; the 192-bit nonce is
why XChaCha20 and not AES-GCM. `decrypt` MUST refuse tag `0x03` and
`decrypt_with_ad` MUST refuse tag `0x02`, so a ciphertext never
authenticates without the associated data it was made with. The tag
byte itself is not part of the associated data, so this holds for the
byte and not for the ciphertext: a `0x03` ciphertext made with empty
associated data, re-tagged `0x02`, opens under `decrypt`. That is a
defect, vauchi/private#949. A degenerate key MUST be refused
(`SymmetricKey::try_from_bytes`); the only degenerate key is the
all-zero one, and `from_bytes_unchecked`, used for keys read back from
storage, skips the check. AES-GCM paths were removed; nothing accepts
them.

**B2. Padding** (`pad`, `unpad`). Before a message is encrypted for the
relay it is padded to a bucket:

```text
len(4, BE) || plaintext || random bytes     to 256, 512, 1024 or 4096 B,
                                            above 4096 to the next 256 B
```

A receiver MAY check `is_valid_bucket_size` and treat any other length
as tampering. The padding bytes are random, not zero.

**B3. Password key derivation** (`derive_key_argon2id`). Argon2id
version 0x13, memory 65 536 KiB, 3 iterations, parallelism 4, 32 bytes
out, with a 16-byte random salt. Test builds use 8 MiB and one
iteration; a vector produced by a test build does not match.

---

## C. Storage at rest and crypto-shredding

Source: `vauchi-core/src/storage/`, `crypto/cek.rs`,
`api/shred/`, `api/vauchi/storage_keys.rs`.

**C1. What is encrypted under what.** SQLite with application-level
encryption: sensitive columns hold tagged ciphertexts (B1).

- A contact's card JSON is encrypted under the contact's **content
  encryption key** (CEK), a random 32-byte key, and the CEK under the
  SEK; a contact without a CEK has its card under the SEK directly
  (`contact_to_row`). Destroying one CEK erases one card.
- The contact's shared key and visibility rules are encrypted under
  the SEK (`test_visibility_rules_stored_encrypted_not_plaintext`).
- Ratchet states are encrypted under
  `HKDF(SEK, "vauchi-ratchet-storage-v1:" || contact_id)`.
- The identity row holds the seed under the SEK.

**C2. Key check** (`storage/key_check.rs`). The database carries a row
sealing a fixed label under `HKDF(SEK, "Vauchi_Storage_Key_Check_v1")`,
so opening with the wrong key fails as `WrongKey` instead of reading
garbage; a database from before the row proves its key through the
identity row and only then gets one.

**C3. Shredding** (`api/shred/storage.rs`, `api/shred/manager.rs`).
Erasure MUST first delete the SMK and the bootstrap key from secure
storage by name (`destroy_storage_keys`, `secure_delete_key`). Then it
overwrites and removes the identity file, the key files and the
database with its WAL and SHM files, and removes the data directory.
On flash storage an overwrite may not reach the old blocks, so it is
deleting the keys that makes the rest unreadable. The SEK and FKEK are
never stored: they exist only derived from the SMK in memory.

### Security considerations

- **Destroying the SMK makes the data unrecoverable**, claim
  [S12](../claims.md): `test_smk_destruction_makes_data_irrecoverable`
  in `smk_boot_tests.rs` deletes the SMK and the database no longer
  opens; its namesake in `crypto_shredding_integration_tests.rs`, with
  `test_fkek_protects_file_keys` and
  `test_shredding_isolation_across_identities`, shows that the keys are
  separated; the e2e repository's release lane case
  `hard_shred_after_grace_fanout_over_outer_hop_only`
  (`tests/it/action_family_oracles.rs`) runs the shred. Partial: on
  Android and iOS the platform key-destruction step is incomplete.
- The seed is in the database under the SEK, and the SMK that opens
  the database is in the keychain: an attacker who can read the
  keychain's raw bytes has the seed. The design argument is that a
  software wrapper would only move that problem (`shredding.rs`).
- One identity's keys open nothing of another's: the hierarchy is
  rooted in the seed, and the isolation test above checks it.

---

## D. Backups

Source: `vauchi-core/src/identity/mod.rs` (v2),
`backup/full_backup.rs` (v3 and v5), `backup/snapshot/` (v6, v7),
`backup/contact_backup.rs`, `backup/key_shard.rs`,
`api/vauchi/full_backup.rs`.

**D1. Identity backup, v2** (`Identity::export_backup`). The password
MUST pass the strength check (score 3 of 4, at least 8 bytes of
UTF-8, not 8 characters, `identity/password.rs`). Then

```text
0x02 || salt(16) || Enc(K2, name_len LE u32 || name || seed(32)
                            || device_index LE u32 || device_name_len LE u32 || device_name)
K2 = Argon2id(password, salt)
```

Import accepts version `0x02` only and parses the plaintext with
declared lengths that must fit (`a_plaintext_whose_lengths_overrun_it_is_refused`).
Bytes after the device name are not refused: `parse_backup_plaintext`
never checks that it reached the end, a defect, vauchi/private#949.
The app's restore (`import_backup`) does not keep the backup's device
index: it registers the install as a new device as a full backup
restore does (D4), with a random index in the upper half of the `u32`
range, a new signing key and a registry version of at least the restore
time. An identity backup carries no registry, so the new device is the
only one listed (`restored_identity_backup_device_tests.rs`,
vauchi/private#970). The restore brings back no contact and no session:
a contact met before keeps the keys of the first exchange (In-Person
Exchange B12), so the restored install cannot resume it by meeting it
again (vauchi/private#1285). A social-recovery restore takes a new index too
(Social Recovery A11, planned).

**D2. Full backup, v3** (legacy, still imported). `0x03 || salt(16) ||
Enc(K3, zlib(JSON))` with

```text
K3 = HKDF-expand(HKDF-extract(none, Argon2id(password, salt)), "vauchi-backup-v3", 32)
JSON = { version: 3, created_at, sections: { identity: { display_name,
        master_seed_b64, device_index, device_name }, contacts: [...],
        own_card?, labels?: [{ label_id, name, contacts }] } }
```

Each contact entry carries its card JSON and, for an exchanged
contact, its identity key, its **shared key** and its visibility rules
(`ContactBackupEntry`); all of it is inside the ciphertext. The
plaintext MUST start with the zlib magic `0x78` on import.

**D3. Full backup, v6** (written until v7, still imported). The
header is in the clear and authenticated:

```text
header = 0x06 || salt(16)
file   = header || AEAD_0x03(K6, zlib(JSON snapshot); AD = header)
K6     = HKDF-expand(HKDF-extract(none, Argon2id(password, salt)), "vauchi-backup-v6-state", 32)
```

The snapshot is `{ version: 6, created_at, identity, own_card,
contacts, groups, overrides }`: the v3 contact entries plus each
contact's hidden, blocked, favourite, archived, ignored and
relationship state (transport, proximity, trust metrics, reciprocity),
the groups, and the per-contact field overrides. A reader dispatches
on the version byte: 7 to D4, 6 to D3, anything else to the v3
importer, which rejects anything but 3.
The file is at most 32 MiB and decompresses to at most 64 MiB; the
whole snapshot is validated (names, field counts, avatar bytes and
dimensions, unique ids) before any write, and the restore is one
transaction on a fresh installation only
(`full_backup_validation_rejects_invalid_state_before_mutation`).

**D4. Full backup, v7** (what `Vauchi::export_full_backup` writes
today; ADR-080 point 7). Two payloads of one size behind a clear,
authenticated header:

```text
header  = 0x07 || file_id(16) || salt_0(16) || salt_1(16)
file    = header || P_0 || P_1, with |P_0| = |P_1|
P_i     = AEAD_0x03(K_i, frame_i; AD = header)
K_i     = HKDF-expand(HKDF-extract(none, Argon2id(password_i, salt_i)), "vauchi-backup-v7-payload", 32)
frame_i = u32_be(len(z_i)) || z_i || zero bytes to the bucket
z_i     = zlib(JSON snapshot)
bucket  = 4096, 8192, ... doubling; past the last power of two that
          fits twice in the 32 MiB file: (32 MiB - 49) / 2 - 41
```

The snapshot is D3's with `version: 7`. Exported from the real
profile of an install with an app password, it also carries `duress`:
the mask profile's rows re-encrypted under a fresh transfer key with
that key, the app password's hash and salt, and the duress PIN's when
one is set. The duress credential marks `password_branch: true` when
it was set up under the password branch, where the app password and
the duress credential both pass D1's rule because the device has no
biometric unlock (ADR-032, amended 2026-11-10); the field is written
only then, so a biometric-branch section is the same as before it
existed, and a reader from before it refuses a password-branch one. A
restore saves the credentials with their branch and re-encrypts the
mask under the new device's mask key, so it locks as before and the
duress PIN opens the same mask
(`a_restored_install_opens_the_old_decoys_under_the_old_mask_with_the_duress_pin`,
`a_restore_keeps_the_password_branch`).
The real payload also carries `device_registry`, the registry the
install signed with, naming each device's signing key; a decoy payload
and older files have none, and a reader from before it refuses a file
that has one. A restore registers the install as a **new device** of the
identity, never as the backed-up one: signing as that device with a
fresh key would make every contact that pinned it refuse its card deltas
for good (vauchi/private#1247). It takes a device index at random in the
upper half of the `u32` range, clear of the indexes linking hands out
from 0 and of any device the registry lists, adds that device with its
new signing key, and raises the registry version to at least the
restore time in seconds, to avoid reusing the backup's old version.
Contacts still apply their registry freshness checks. The backed-up devices stay
active; at the device limit the backed-up device gives its place to the
new one. Without a registry in the file, the new device is the only one
listed. The next sync pushes the registry to every contact
(`restored_install_card_delta_tests.rs`).
Such a file holds two identities, the real one and the mask's. On the
real profile with a duress PIN, `export_full_backup_with_decoy` fills
the other payload under a decoy backup password: the mask profile under
the mask identity, locked with the duress PIN and with no duress of its
own. The export refuses a backup or decoy password that unlocks the
install or repeats the other, with one error
(`a_backup_password_that_unlocks_the_install_is_refused`). The real
payload takes a random slot. Without a decoy password, the other payload is a zero
frame under a random key. Both payloads are padded to the bucket of the
larger, and every export draws a fresh file id, salts and nonces. A
reader derives both `K_i` before trying either, so a restore takes the
same time whichever payload opens or neither, and every failure,
including a payload taken from another file, is `DecryptionFailed`
(`payloads_from_another_file_do_not_open_under_this_header`). A
reader cannot check the payload it does not open. A reader from
before v7 refuses the file
(`full_backup_state_old_reader_rejects_richer_password_backup`);
limits and validation are D3's.

**D5. Guardian backup, v5** (`export_guardian_backup`). The v3
`FullBackupEnvelope` of D2 (with `version: 5`), not the v6 snapshot,
encrypted under a random 32-byte backup key `B`, which is
split among guardians by Shamir's secret sharing (`key_shard.rs`, see
[Social Recovery](social-recovery.md)):

```text
prefix = 0x05 || threshold(1) || count(1) || ceremony_id(16) || salt(16)
conf   = HMAC-SHA256(HKDF(salt, B, "vauchi-backup-v5-key-confirmation-key"),
                     "vauchi-backup-v5-key-confirmation" || prefix)[0..16]
header = prefix || conf
file   = header || AEAD_0x03(HKDF(salt, B, "vauchi-backup-v5-guardian"), zlib(JSON); AD = header)
```

`conf` lets a holder check a reconstructed key against the file before
decrypting (`guardian_backup_key_matches`, constant time).

**D6. What the app offers.** The backup wizard's default level is
*Full*; *Identity only* (v2) is the opt-in
(`vauchi-app/src/ui/backup_recovery/`; ADR-058 amendment 2026-10-28,
Option D). Both exports run the password strength check of D1:
`export_full_backup` has run it since `5101a890c`
(vauchi/private#891), so the file that holds every contact's shared
key is held to the same password as the identity-only one.

### Failure cases

- Wrong password: the AEAD fails, `DecryptionFailed`; no partial
  plaintext is ever produced (`full_backup_api_wrong_password`,
  `test_v2_wrong_password`).
- Wrong version byte, file over 32 MiB, plaintext not zlib or over
  64 MiB, invalid state: refused before any write.
- Import onto an installation that already has an identity:
  `AlreadyInitialized`.

### Security considerations

- **A backup without its password reveals nothing** beyond its version
  byte, salts, file id and length (for v7, the bucket), claim
  [S13](../claims.md):
  `v2_backup_encrypts_the_seed_and_leaks_no_key_material`,
  `test_v2_wrong_password`,
  `backup_debug_output_carries_no_secrets_or_contact_data`, vectors
  entries `backup` (v3), `backup_v6` and `backup_v7`. The v7 header,
  file id included, is authenticated
  (`backup_v7_vector_opens_its_real_payload_under_its_header_only`,
  `backup_v7_vector_imports_with_production_argon2id_and_refuses_a_wrong_password`).
  The v6 header is
  authenticated, so a changed salt or version fails the tag
  (`full_backup_validation_authenticates_header_and_ciphertext`,
  `backup_v6_vector_decrypts_under_its_header_and_not_under_a_changed_one`),
  and the v6 vector is imported through `import_full_backup` with the
  production Argon2id parameters
  (`backup_v6_vector_imports_with_production_argon2id_and_refuses_a_wrong_password`).
- A full backup contains every contact's shared key and card. Its
  strength against guessing is the password through Argon2id (B3),
  held to the strength check of D1 like the v2 export (D6).
- The backup is the seed: see A's note on clones.

### Vectors

`identity` (A2, A3 for index 0), `backup` (D2's key derivation and a
complete v3 file), `backup_v6` (D3's header, base key, final key
and a complete file) and `backup_v7` (D4's header, the slot the
password opens, its base key and payload key, and a complete file) in
[Test Vectors](../vectors.md). The v5
derivation is not in the vectors yet.

---

## E. Device link

### Message flow

```text
Existing device (host)                                   New device (joiner)
  | QR = "WBDL" || 0x01 || id || lk(32) || t(8) || sig_id
  |---------------------------------- (camera) ------------------------>|
  |                                              verify sig; refuse if t + 300 < now
  |<--- Enc(lk, name_len || name || nonce(32) || t_req) ---------------|  via relay slots
  | code = f(lk, nonce)                                code = f(lk, nonce)
  | user compares the two codes and the fingerprint, confirms on the host
  |---- Enc(lk, seed || display name || index || registry || sync JSON) ->|
  |                                              pk(seed) == id ? adopt : refuse
```

`lk` is the link key, `t` the QR timestamp, `sig_id` the identity's
signature over `0x01 || id || lk || t`.

### Normative operations

Source: `vauchi-core/src/exchange/device_link/` (`qr.rs`, `request.rs`,
`types.rs`, `initiator.rs`, `responder.rs`, `response.rs`,
`refusal.rs`, `invitation.rs`), `api/vauchi/identity.rs`;
`vauchi-app/src/orchestrator/device_link_*`.

**E1. Link QR** (`DeviceLinkQR::generate`). 141 bytes, standard
base64: magic `WBDL`, version 1, the identity key, a fresh random
32-byte link key, the timestamp, and the identity's signature over the
four fields after the magic. A parser MUST verify the signature and
refuse any other version; the QR expires 300 s after its timestamp
(`LINK_QR_EXPIRY_SECONDS`, ADR-035), checked with a checked addition.
The parser reads the first 141 bytes (`split_first_chunk::<141>`) and
ignores any that follow, a defect, vauchi/private#949.
Off camera, the same payload travels as a join invitation URL with the
relay's broker code (`invitation.rs`); the trust argument then rests on
whatever channel carried the URL.

**E2. Request** (`DeviceLinkRequest`). `name_len LE u32 || name ||
nonce(32) || timestamp LE u64`, encrypted with tag `0x02` under the
link key. The host MUST refuse an empty name and a name an active
device already has (`SelfLinkingNotAllowed`, a name-based stand-in for
a device-id check the request does not carry).

**E3. Confirmation code** (`derive_confirmation_code`).

```text
code = u32_be(HMAC-SHA256(HKDF(lk, "vauchi-device-link-confirm-code-v1"), nonce)[0..4])
       mod 1_000_000, shown as "ddd-ddd"
```

Both devices show it with the identity fingerprint. The host MUST NOT
release the seed without a proximity proof: today the proof is
`ManualConfirmation { mac, confirmed_at }` with `mac = HMAC-SHA256(
HKDF(lk, "vauchi-device-link-confirm-mac-v1"), code)` and at most 60 s
old (`validate_proximity_proof`, constant-time compare;
`ProximityExpired`, `ProximityNotVerified`). The age is
`now.saturating_sub(confirmed_at)`, so a `confirmed_at` in the future
counts as zero seconds old and passes, a defect, vauchi/private#949.

**E4. Response** (`DeviceLinkResponse`). The master seed, display
name, the index the host assigned (A4's next index), the updated
signed registry and a JSON sync payload, encrypted under the link
key. The payload (`sync/device_sync/payload.rs`) carries the contacts
with their shared keys and visibility rules, the imported contacts,
the own card, tags, groups, places, exchange locations, the contacts'
device registries and activations; it carries no ratchet states. A refusal (`Declined`, `ConfirmationTimedOut`, `DeviceNameTaken`,
`Cancelled`) travels on the same return channel under a separate key
`HKDF(lk, "vauchi-device-link-refusal-v1")`, so it can never decrypt
as a response.

**E5. Adoption** (`DeviceLinkResponder::process_response`,
`adopt_device_link_response`). The joiner MUST refuse a seed whose
Ed25519 key is not the QR's identity key (`IdentityMismatch`,
vauchi/private#789): anyone with a copy of the QR holds the link key
and could otherwise hand it a seed of their choosing. It MUST refuse
to adopt when it already has an identity. It then derives the identity
with the given index, saves the registry and applies the sync payload.
The adoption path does not re-verify the registry's signature; the
registry arrived under the link key from the device that signed it.

### State machine

Host (`DeviceLinkInitiatorMachine`): `Preparing` → `AwaitingClaim` →
`AwaitingConfirmation` (60 s for the user) → `Finalizing` →
`Completed`; `Failed` on expiry or refusal, `Cancelled` by the user.
Joiner: `Idle` → `Scanning` → `AwaitingResponse` → `Completed`,
`Failed`, `Cancelled`. The relay slots live 300 s. The Quint model
`device_link_machines.qnt` checks `joiner_seed_implies_registered` and
`no_device_registered_for_a_failed_joiner` on a reliable relay; the
same model shows (`lossy_relay`) that a response lost after the host
confirmed leaves a registered device that never received its seed,
because the registry is saved before the response is known delivered,
and (`before_808`) that without the host's expiry check at finalize a
failed joiner could be registered.

### Failure cases

- Expired or unsigned QR, wrong version: refused at scan.
- Taken or empty device name: refused at the host, `DeviceNameTaken`
  sent back.
- Proof missing, stale or wrong: the seed is not released.
- Seed of another identity: `IdentityMismatch`, nothing adopted.
- Response lost: the host has registered a device that holds no seed;
  the owner revokes it (A4).

### Security considerations

- **The seed stays secret unless a link QR was photographed**, and
  each side agrees with the other, claim [S15](../claims.md):
  `seed_secrecy`, `initiator_agreement`, `joiner_agreement`,
  `photographed_qr_alone_keeps_the_seed` in `device_link.spthy`, and
  the attack lemmas `qr_leak_exposes_seed` and
  `qr_leak_lets_attacker_choose_joiner_identity` (the second is what
  E5's check closes in code; the model predates it).
- **A photographed QR** gives the link key. Against an honest relay
  the code stops the attacker's own request: the user's new device
  shows a different code. Against a relay the attacker reads, the
  attacker decrypts the seed while both devices see matching codes.
  The six-digit code is a comparison aid; an attacker who holds the
  link key can find a nonce with the same code in about a million
  HMACs.
- The seed in E4 is the whole identity (A). A compromised new device
  can derive every device's keys.

### Vectors

None yet. Candidates: a link QR with its signature, the confirmation
code and proof MAC for one link key and nonce.

---

## F. Duress

Source: `vauchi-core/src/api/app_password.rs`,
`api/vauchi/security.rs`, `api/vauchi/duress_concealment.rs`,
`api/vauchi/duress_cover.rs`, `api/vauchi/contacts.rs`,
`sync/device_sync.rs`, `emergency.rs`.

**F1. Two credentials.** The app password and the optional duress PIN
are each stored as `Argon2id(credential, salt16)` (B3 parameters) with
their own salt. The duress PIN MUST be exactly 6 ASCII digits and MUST
NOT equal the password. `AppPasswordConfig::verify` MUST hash the
input against both salts every time and compare both in constant time;
the password wins when both match. After a platform biometric, Core
answers in no less than a fixed minimum time whether a PIN prompt is
needed, so the presence of a duress PIN does not show in the unlock
animation. Nor does it show to someone who images the storage without
the SMK. Every identity with an app password MUST carry a duress salt
and a duress seal, `Enc_SEK(flags || hash)`
(`storage/stores/identity.rs`): with no PIN set, a random salt and a
random hash with the flags 0, written with the app password and again
when the PIN is disabled. The plain `duress_enabled` column MUST stay
0. The flags say whether a PIN is set and whether a duress session has
taken the own-card copy over (F2). Since a duress hash always exists,
`verify` always runs both Argon2id hashes. The SQLite file is not
itself encrypted, so what remains readable is each row's shape, and
the identity row and the own-card copy have the same shape with or
without a PIN. Decoy contacts and the duress session's groups, tags
and places MUST NOT have rows of their own in the file: they live in
one `duress_content` row every database has (`storage/duress_content.rs`),
`Enc_SEK(len || rows || padding)` padded to 4 KB and then to the next
doubling, sealed empty when there are none. What remains readable is
that size bucket. Guessing
the PIN needs the SMK; with it, the seal says whether a PIN is set, and
a six-digit PIN under Argon2id is about a million guesses offline. The duress PIN defends against a coercer who watches the
unlock, not one who extracts the database and the keychain, and the
second already holds the data (the limit F3's model states).

**F2. What a duress unlock shows.** `auth_mode` becomes `Duress`.
Contact listing and lookup answer only decoy contacts, built from the
decoy store with a display-only fake key `SHA-256(id)` and a random
shared key. The own card shown is a session copy seeded from the real
card; edits touch the copy. Every identity with an app password has the
copy, made from the real card with the password and again when the PIN
is disabled, so its row does not say whether a PIN exists. The duress
and decoy settings screens
answer from a session stand-in that starts as "not set up" and accepts
whatever is entered, so the coercer can neither see nor change the
real configuration; the stand-in is dropped at the next unlock. The
real card, contacts and keys are untouched.

**F3. Cover traffic.** An own-card edit under duress MUST NOT reach a
contact and its absence MUST NOT show either. For every contact the
real path would reach, the next sync queues a cover payload of the
length that contact's delta would have had, through the same ratchet
session (`queue_cover_for_contact`); the receiver opens it as nothing
(`ReceiveOutcome::Cover`). Items journaled for the owner's other
devices are replaced by cover items of the same serialized length and
timestamp (`SyncItem::cover_of`). The pending counters and the wire
look like a normal edit.

### Security considerations

- **A duress unlock shows a decoy and sends nothing that reveals it**,
  claim [S14](../claims.md), partial. Tests
  `applying_a_cover_item_changes_nothing` and
  `a_cover_item_has_the_length_and_timestamp_of_the_item_it_stands_for`
  in `duress_cover_device_sync_tests.rs`;
  `bob_opens_a_duress_cover_as_nothing_and_a_real_edit_as_the_edit`
  and the property tests in `duress_cover_tests.rs`. The Tamarin file
  `duress_cover.spthy` is a diff model: a normal unlock sending the
  coercer's edit and a duress unlock sending cover are observationally
  equivalent to a coercer who watches network and relay, and the
  equivalence is falsified when the coercer also extracts the ratchet
  keys from the device, which is the design's limit. The model states
  no named lemma beyond executability.
- The model abstracts sizes and timing; the code pads cover to the
  delta's length and sends it on the same sync, which is what the
  equivalence assumes.
- A coercer who already knows a contact's card can ask to see it; the
  decoy list does not contain it. What duress protects is the
  contact list and the keys, not the fact that the app exists.

---

## G. Cards, visibility and trust

Source: `vauchi-core/src/card/`, `visibility.rs`,
`api/vauchi/visibility.rs`, `sync/delta.rs`, `contact/trust.rs`,
`contact/trust_metrics.rs`, `contact/mod.rs`.

**G1. Card** (`ContactCard`). `{ schema_version: 1, id, display_name,
fields, avatar?, bio?, field_visibility }`, serialized as JSON; there
is no canonical byte encoding, and what is signed on the wire is the
delta of the sync chapter, not the card. Limits refused on input:
display name 1 to 100 characters after text normalisation; bio 160
characters; 200 fields; a field's value 1 000 bytes; the whole card
65 536 bytes of JSON. Limits enforced by truncation, not refusal: a
field's label to 64 characters and its note to 500. The avatar is any
common image, normalised to WebP of at most 32 768 bytes and 512 px
(ADR-042). A field has a type (`Phone`, `Email`, `Social`,
`Address`, `Website`, `Birthday`, `Custom`) with per-type validation
(`field.rs`, `uri.rs`).

**G2. Visibility.** A field's rule is `Everyone`, `Contacts(set)` or
`Nobody`; a field with no rule is **hidden** on the own card and on
the wire (`ContactCard::is_field_shown`,
`get_effective_field_visibility`), even though the rule type's
fallback value is `Everyone`. What a contact receives is decided per
field, in this order: a per-contact override; a grant from a group
the contact is in; a field assigned to any group is hidden from every
contact without a grant; otherwise the contact's stored legacy rules
must allow the field (`can_see`; an imported contact has none, so it
gets nothing here), and then the own-card toggle decides, visible
only on an explicit `Everyone` (`api/vauchi/visibility.rs`). The
display name is always sent. The
default-open filter `CardDelta::filter_for_contact` MUST NOT drive
outbound propagation (ADR-054 G4); `filter_with` and the effective
visibility do. New fields default to hidden
(`no_groups_mode_defaults_hidden_until_toggled`).

**G3. Trust level** (`Contact::trust_level`). Derived, never set:

```text
Cautious  if the contact's identity was recovered (until the fingerprint is re-verified)
Verified  if the owner marked the fingerprint verified out of band
Remote    if the contact was exchanged over a link
High      if the transport proximity is Physical (USB) or ContactRange (NFC),
          or the exchange's proximity confidence is High
Standard  otherwise
```

A contact stored before trust metrics existed is High only when its
proximity confidence is High and it was exchanged over NFC or BLE
(`contact/mod.rs`). An imported contact is always Standard.

Remote ranks below Standard but is evaluated before High, so a proximity
claim on a link contact cannot raise it. Only a fingerprint comparison does,
to Verified. A Remote contact cannot be marked for recovery. The level is
derived and not stored, and device sync carries the transport (E), so every
device shows the same level.

`mark_fingerprint_verified` sets `Verified` and clears the recovered
flag. A move checked against the contact's commitment (Social Recovery
D7, ADR-034 amendment) keeps the level and does not set the recovered
flag; a moved identity confirmed in person without a commitment (D8)
keeps today's rule. The metrics behind the decision (transport, confidence, the
transport's proximity class, timestamp) are stored with the contact so
the level is auditable.

### Security considerations

- **Trust follows how you exchanged and cannot be edited**, claim
  [S10](../claims.md): `the_trust_shown_follows_the_exchange_and_cannot_be_tapped`
  in `vauchi-app/tests/it/contact_trust_tests.rs`. No command sets a
  level; the shell shows what Core derived.
- Visibility is enforced at the sender: a contact never receives a
  field it was not granted, so a revoked grant stops future updates
  but does not recall what was sent.
- The two defaults in G2 are a sharp edge for anyone reading the code:
  the rule type says `Everyone`, the product says hidden. The outbound
  path takes the second.

---

## Sources

- `vauchi-core/src/identity/mod.rs`, `identity/device.rs`,
  `identity/password.rs`; `crypto/signing.rs`, `crypto/kdf.rs`,
  `crypto/password_kdf.rs`, `crypto/encryption.rs`,
  `crypto/padding.rs`, `crypto/shredding.rs`, `crypto/cek.rs`
- `vauchi-core/src/storage/key_check.rs`, `storage/stores/contact_row.rs`,
  `storage/stores/ratchet.rs`, `storage/stores/identity.rs`;
  `api/vauchi/storage_keys.rs`, `api/shred/storage.rs`,
  `api/shred/manager.rs`; `sync/device_sync/payload.rs`
- `vauchi-core/src/backup/full_backup.rs`, `backup/snapshot/codec.rs`,
  `backup/snapshot/mod.rs`, `backup/contact_backup.rs`,
  `backup/key_shard.rs`; `api/vauchi/full_backup.rs`;
  `vauchi-app/src/ui/backup_recovery/`
- `vauchi-core/src/exchange/device_link/*`, `api/vauchi/identity.rs`;
  `vauchi-app/verification/device_link_machines.qnt`
- `vauchi-core/src/api/app_password.rs`, `api/vauchi/security.rs`,
  `api/vauchi/duress_concealment.rs`, `api/vauchi/duress_policy.rs`,
  `api/vauchi/duress_cover.rs`,
  `sync/device_sync.rs`
- `vauchi-core/src/card/mod.rs`, `card/field.rs`, `visibility.rs`,
  `api/vauchi/visibility.rs`, `sync/delta.rs`, `contact/trust.rs`,
  `contact/trust_metrics.rs`
- `vauchi-core/verification/device_link.spthy`, `duress_cover.spthy`
- ADR-007 (domain separation), ADR-033 (SMK), ADR-035 (link QR
  expiry), ADR-042 (avatars), ADR-054 (visibility), ADR-058 (backups),
  ADR-032 (duress)
