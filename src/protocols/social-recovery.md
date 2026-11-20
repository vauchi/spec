<!-- SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- description: How Vauchi social recovery is specified: guardians chosen in advance hold sealed shares to restore an identity; the step letting contacts accept it is partial. -->

# Social Recovery

> **Status: extracted 2026-10-28** from `vauchi/core` `612992b0b` and
> `vauchi/relay` `9b869ac3b`. Two mechanisms share this chapter: the
> **guardian backup** (section A), which gives a person back their
> seed and contacts from shares their guardians hold, and **recovery
> vouching** (section B), which tells a contact that a new identity is
> the same person. Section C is what follows for the old contacts,
> most of which is open work. Claims backed: [S16](../claims.md),
> [S17](../claims.md).

## Goal

A person who loses every device, and with it the seed, can get their
identity and contacts back through people they chose in advance, with
no password to remember; and a contact who hears "this new key is me"
can tell a real recovery from a thief holding the old device. Nobody
below the threshold of guardians learns anything, and the relay that
stores the pieces can read none of them.

## Actors

- **Owner** (Alice): designates guardians while she still has her
  device; later recovers with a new identity.
- **Guardians**: contacts holding a sealed share; three to nine, or
  three to nine groups of one to three members.
- **Helpers**: contacts who vouch in person that the old and new keys
  are the same person; a guardian can be one.
- **Contact** (John): decides whether to accept the recovery.
- **Thief**: holds the old device, with its identity key and every
  shared key on it.
- **Relay**: stores sealed guardian entries and recovery proofs it
  cannot read, seeing only each proof's version byte and new key; the
  attacker of both models owns it and the network.

---

## A. Guardian backup

### Message flow

```text
Owner                                   Guardian G_i                 Relay
  | B = random 32 B; file = v5 backup under B (Keys and Cards, D5)
  | shares = Shamir(B, t, n); share_i sealed to G_i's X25519 key
  |-- sealed share_i (in person or any channel) -->|
  | token_i = sign_owner("vauchi-recovery-guardian-v1" || owner || G_i || created_at)
  |-- guardian set { seal(token_i) }, signed store ----------------------->| under SHA-256(owner_pk || "guardians")
  ...device lost; new identity N...
  | claim = (old_pk, new_pk, timestamp)  shown as QR                  |
  |-- claim ------------------------------------->| opens its token from the relay set,
  |                                               | vouches (B1) and re-seals share_i to N
  |<-- voucher_i, seal_N(share_i) ----------------|
  | t shares → B → file opens → seed, contacts, cards, groups
```

### Normative operations

Source: `vauchi-core/src/crypto/shamir.rs`, `backup/key_shard.rs`,
`backup/guardian_groups.rs`, `backup/guardian_recovery.rs`,
`backup/full_backup.rs`, `recovery/sealed_box.rs`,
`recovery/guardian.rs`, `api/vauchi/identity.rs`,
`api/vauchi/recovery.rs`; `relay/src/guardian_storage.rs`,
`handler/verify.rs`.

**A1. Split** (`split_backup_key`, `shamir::split`). The backup key `B`
of a v5 file is split by Shamir's secret sharing over GF(256) with the
AES polynomial `0x11b`: the secret is the constant term of a random
polynomial of degree `t - 1`, share `i` is its value at `x = i`, `i`
from 1 to `n`. Limits: `2 ≤ t ≤ n`, `3 ≤ n ≤ 9` (`KeyShardConfig`).
Each shard is serialized as

```text
0x02 || threshold(1) || count(1) || ceremony_id(16) || index(1) || value(32)
```

The ceremony id is random per backup and ties shares to one file.
Kani harnesses cover interpolation with the field multiplication
stubbed, one byte's recovery with the interpolation stubbed, and the
refusal of more shares than guardians; one byte through the real
arithmetic did not finish in 10 minutes, so the exhaustive `gf_mul`
and `gf_inv` unit tests stay the evidence for the field
(vauchi/private#937)
(`interpolation_never_panics_and_refuses_a_zero_or_repeated_x`,
`recover_byte_never_panics`,
`reconstruct_refuses_more_shares_than_guardians`); unit tests check
the field multiplication against an independent reference.

**A2. Groups** (`GuardianGroups`, vauchi/private#815, #796 D17).
Recovery needs one member from each group: a grouped backup is a split
with `t = n = number of groups`, and a group's share is sealed to each
of its members. The bounds are 3 ≤ groups ≤ guardians ≤ 9, with no
group empty and no limit on a group's size; "all of three guardians" is
three groups of one. The owner puts each guardian in a group as it is
added (`trust_for_recovery_in_group`), and the guardian backup is split
over those groups; fewer than three groups make no backup.
`one_member_from_each_group_recovers`,
`members_of_one_group_count_as_one`,
`a_whole_group_missing_blocks_recovery`,
`a_group_may_hold_more_than_three_and_one_of_each_group_opens`.

**A3. Sealing** (`seal_share_for_guardian`, `sealed_box::seal`). A
share is sealed to the guardian's X25519 key, obtained from its Ed25519
identity key by the Edwards-to-Montgomery map
(`ed25519_pk_to_x25519`); the guardian opens with the X25519 secret
derived from its signing seed exactly as Ed25519 derives its scalar
(SHA-512, clamped; `to_x25519_secret`,
`identity_opens_share_sealed_to_its_signing_key`). The sealed box is

```text
ephemeral_pk(32) || nonce(24) || XChaCha20-Poly1305(key, nonce, shard)
key = HKDF-SHA256(salt = none, ikm = X25519(e, pk), info = "vauchi-sealed-box-v1")
```

with a fresh ephemeral key per seal, so the sender is anonymous; a
small-order recipient key MUST be refused (`WeakKey`). There is no
associated data, and neither `ephemeral_pk` nor the recipient key
enters the key derivation, unlike HPKE (RFC 9180) or libsodium's
sealed box: the ciphertext authenticates the shard, not the keys it
was sealed between. A sealed shard is exactly `32 + 24 + 52 + 16` =
124 bytes.

**A4. Guardian designation** (`GuardianToken`,
`upload_guardian_entries`). For each contact marked recovery-trusted
the owner signs a token over `"vauchi-recovery-guardian-v1" ||
owner_pk || guardian_pk || created_at as LE u64`, seals it to that
guardian (A3), and stores the set on the relay under
`SHA-256(owner_pk || "guardians")` with a request signed over
`"guardian-store" || owner_pk || hash || timestamp as BE u64`, which
does not cover the entries (each token carries its own signature); an
empty set is a signed `"guardian-delete"`. Core trusts at most nine
contacts for recovery, the guardian maximum; a tenth is refused where
the switch is, and a guardian count is checked before it is narrowed
to a byte (vauchi/private#929). The relay MUST verify the
signature, the hash binding and a timestamp within 60 s, refuse a
replayed signature, keep at most
10 entries of at most 256 bytes and 2 048 bytes in all, expire the set
after 365 days, and answer a query for any hash with the sealed
entries: the hash is public and the entries are opaque.

**A5. Response** (`respond_to_recovery`). A guardian opens its share
with its own X25519 secret and re-seals it to the recovering
identity's key (A3 again). Nothing of the share is shown or leaves the
device in the clear. The re-seal is a separate call from vouching
(B2) and checks neither a claim nor a token: the guardian decides, in
person, which key it answers.

The hand-back (`return_guardian_backup`) does check: in the recovery
meeting the recovering identity and the guardian also run an in-person
exchange (In-Person Exchange), and over that session the guardian
returns its share re-sealed to the contact's key together with the
delivery it keeps (A8), as ratchet messages of version `0x0d` in A7
pieces. A guardian MUST hand back only to a contact whose key is the
new key of a claim it vouched for (B2), within the claim's maximum age
of 192 hours from the vouch, and only the delivery kept for that
claim's old key. The old device's key is a vouched claim's old key and
never its new one, so a thief exchanging with it gets nothing. A duress
session MUST answer as a guardian holding nothing (ADR-032), with the
same refusal as every other. A receiver MUST keep `0x0d` pieces as a
returned backup and never as a designation (A8).

The hand-back starts by itself (`hand_back_owed`): the completed
exchange with the claim's new key queues it, and so does every sync
after, so a guardian that answered the exchange, and has no sending
chain until the new phone writes first, sends it then. Each vouched
claim is handed back once; an ordinary exchange hands nothing back.

**A6. Restore** (`recover_guardian_backup`, `recover_from_shards`).
The recovering identity opens each re-sealed response with its own
secret, keeps those whose metadata matches the file's header, at most
`n + 1` distinct ones out of at most 18 responses, and tries
threshold-sized subsets in order: a candidate key is checked against
the file's 16-byte key confirmation (Keys and Cards, D5) before the
AEAD open, so at most C(10, 5) = 252 subsets are tried, in the worst
case of 5 of 9 guardians.
The first key whose AEAD authenticates yields the envelope; the caller
restores it like a password backup. Responses do not authenticate
their sender, so several injected responses with the right metadata
can displace honest ones from the bounded set and deny the recovery;
they cannot make a wrong key accepted.

**A7. Delivery in pieces** (`split_into_pieces`, `PieceAssembly`,
`encode_guardian_backup_piece`). A guardian keeps the owner's
encrypted file next to its share (vauchi/private#796, D7), but the
relay caps a request body at 128 KB and a file with avatars runs to
megabytes. The delivery, of at most the file's 32 MiB cap plus 64 KiB,
therefore travels as ratchet messages of version `0x0b` (Update and
Sync, B5), each piece at most 48 KiB:

```text
backup_id(16) || count(2, BE) || index(2, BE) || SHA-256(delivery)(32) || body
```

Every body but the last is exactly `48 KiB - 52` bytes, so a
delivery's size follows from its count. A receiver MUST refuse a
piece with a count of zero or above the cap, an index not below the
count, or a body of the wrong length, before anything reads it; it
MUST take pieces in any order, MUST treat a second copy with the same
bytes as no change, and MUST refuse a second copy with other bytes, a
piece of another backup, count or hash, and a completed delivery whose
SHA-256 differs. The ratchet authenticates the sender; a blocked
contact's piece is refused like any of its messages.

The delivery the pieces carry (`GuardianDelivery`) is

```text
created_at(8, BE seconds) || share_len(2, BE) || sealed share || file
0x01 || created_at || share_len || sealed share || token_len(2, BE) || token || file
```

with a share of 1 to 1 024 bytes and a non-empty file. `created_at` is
the owner's time of export; random backup ids and mailbox arrival carry
no order, and the ratchet authenticates the owner who set it. The
second form carries the guardian's token (A4's `GuardianToken`, 1 to 1
024 bytes): the owner's key naming this guardian, so the guardian's
in-person vouch can show it is one of the owner's (B2,
vauchi/private#796 D19). Since the old key signs it, it authorizes no
rekey (C3). The owner sends the second form; the first
starts with the creation time's high byte, zero for any real time, and
still reads, without a token.

**A8. Keeping** (`GuardianBackupStore::keep_piece`). A guardian keeps
each owner's newest whole delivery, encrypted at rest. It MUST keep a
piece in the same transaction that advances the ratchet, so a storage
failure leaves the message on the relay to be fetched again. A whole
delivery replaces the kept one unless its `created_at` is older; one
that does not add up (a conflicting copy, a hash mismatch, a delivery
that does not decode) MUST be dropped without touching the kept one. At
most two unfinished deliveries wait per owner, and a third evicts the
oldest, so one contact cannot make a guardian hold more. Removing the
owner as a contact removes what it left. A guardian is never told it is
one, and its database does not say for whom either: the rows carry an
HMAC of the owner's contact id under a key derived from the storage
key, never the id, and a storage rekey recomputes it. No single
guardian can read the file: it holds one share, and opening takes one
of every group.

Taking a guardian out of the set sends it a release, a ratchet message
of version `0x0c` with no body (`encode_guardian_release`), in the same
change as the new split for the others. A guardian MUST forget the kept
delivery and the waiting pieces of the release's sender, and only
those, in the transaction that advances the ratchet. A guardian with no
session yet gets no release and keeps what it held.

An owner sends the backup again when what it holds changed: the
voucher threshold, the own card, a contact's key, card or guardian
flag, the groups, or the passphrase (A9), compared by a
domain-separated SHA-256 of them (`refresh_guardian_backup_if_stale`).
It sends at most once a day after the last send, each send being about
2 MB per guardian, and never from a duress session, whose change waits
for the next normal session (ADR-032).

**A9. Passphrase** (`set_recovery_passphrase`,
`backup/passphrase_layer.rs`). The owner MAY set a recovery
passphrase, so that guardians who collude, one of every group, still
open nothing without it. The guardian backup of A7 is then sealed once
more before it is split into pieces:

```text
"VRP1" || salt(16) || XChaCha20-Poly1305(K_p, guardian backup)
K_p = Argon2id(passphrase, salt)
```

The salt is random per passphrase. A passphrase weaker than a backup
password (`validate_password`) MUST be refused: guardians who collude
hold the backup and every share, so they can guess it offline. The owner keeps the salt and `K_p`, encrypted at rest and
rekeyed with the storage key, so a refresh seals again without asking;
setting, changing or clearing it sends the guardians a new backup in
the same change. Restoring, a backup that starts with the magic needs
the passphrase (`guardian_backup_needs_passphrase`), and a missing or
wrong one fails with the same refusal as shares that do not open it
(`recover_guardian_backup_with_passphrase`).

**A10. Restore** (`restore_from_returned_backups`), the path Core ships
today, which A11 replaces (vauchi/private#796, P28). The new identity
(D6) opens the backups its guardians handed back (A5, A8): it tries
every returned share on each returned backup, newest first, since
guardians may hold different deliveries and a share opens only its
own. It MUST keep its own key. In one transaction it restores the
backup's contacts, labels and own card; a contact it already has, such
as a guardian just met again, MUST keep that relationship. Each
restored exchanged contact is marked as waiting for its rekey
(`rekey_pending_contacts`, section C), so restoring again restores
nothing. A share of a group missing, or a missing or wrong passphrase,
fails with the one refusal of A9.

**A11. Restoring the same identity** (`begin_recovery`,
`hand_back_in_person`, `take_hand_back`,
`restore_identity_from_hand_backs`; Core API, ceremony wiring planned,
vauchi/private#796 P28 and
P32). Social recovery is the last way back in, after linking from a
working device and the password backup, and like them it restores the
same identity; it rekeys no contact.

- The new phone has no identity. It makes a temporary recovery key `r`
  and keeps it, with the old identity's key its claim names, encrypted at
  rest until the restore; its claim (B1) names that key and `pk(r)`. A
  phone with an identity MUST refuse to begin; a new target drops the
  hand-backs taken for the old one.
- In person, a guardian that keeps a backup for the claim's old key, and
  only such a guardian, re-seals its share to `pk(r)` (A5) and hands it
  back by QR, with the encrypted backup in Bluetooth pieces in the same
  meeting (P33 and the framing below). Nothing goes through a relay and
  nothing is exchanged as
  contacts. An expired claim, an unknown old key and a duress session
  MUST give the same refusal.
- The phone opens each hand-back's share with `r` as it takes it, and
  MUST refuse one that does not open; it keeps one hand-back per opened
  share, so a retry sealed afresh and two guardians of one group count
  once, and refuses a new share past the shard bound.
- With one share of every group the phone opens the backup with `r`
  (A6, A9). It MUST refuse a backup whose seed does not derive the
  claimed old key, before importing anything: anyone can seal another
  identity's backup to the `pk(r)` a claim shows. Otherwise it becomes
  that identity on a new device index and saves a signed registry
  listing the lost device (derived from the backup's seed and index) as
  revoked and itself as active; it restores the contacts with their
  shared keys, the labels and the own card, then discards `r` and the
  hand-backs. Ratchets are not in the backup:
  sessions restart through the device-registry handshake.
- If the lost device was stolen unlocked, its keys stay exposed:
  revoking it stops its sync and takes nothing from it. Moving contacts
  away from those keys is compromise rotation (section C).

### Recovery backup transport (A11, P33; implementation in progress)

The share is shown by QR and names the encrypted backup's SHA-256. A
backup travels in the A7 piece encoding over the meeting's Bluetooth
link; a receiver MUST accept a backup only when a taken share names its
hash. This does not create a contact or use a relay.

The QR holds the share and a fresh 32-byte attempt token, each in standard
base64, joined by a dot. The token is random per attempt, so a bystander
cannot re-recognise a device across sightings. The guardian advertises the
attempt token that derives from it, as the Glance exchange does, and stays
the GATT peripheral. The phone scans for that advertisement and dials only
a match. The advertisement carries a short prefix, so an unrelated device
can match; the phone still accepts only frames of the backup its share
names. The token authenticates nothing. A phone that already holds the whole
backup a share names takes the share and does not dial.

One encoded piece is at most 48 KiB. The recovery transport fragments it
independently of the contact-exchange chunker: raising that chunker's
256-chunk bound is not required. The sender uses an ATT MTU from 23 to
517 and limits each attribute value to `min(MTU - 3, 512)` bytes.

Each data packet has magic `RBP1`, piece index (`u16` big-endian), byte
offset (`u16` big-endian), encoded piece length (`u16` big-endian), then
non-empty bytes. Its ten-byte header leaves at least ten data bytes at
MTU 23. An acknowledgement has magic `RBA1`, the piece index (`u16`
big-endian) and the exclusive end offset (`u16` big-endian), with no
trailing bytes. The encoded piece length MUST be nonzero and at most
48 KiB; a data packet MUST be at most 512 bytes and its end offset MUST
not exceed that length.

For piece index 1, encoded length 53 and MTU 23, the first data header is
`52425031000100000035` (ten payload bytes follow), its ACK is
`524241310001000a`, and the next data header is
`524250310001000a0035`. These vectors fix byte order and framing only.

The sender MUST keep at most one unacknowledged packet and advance only
on its matching acknowledgement. A duplicate acknowledgement does not
advance it; another piece's acknowledgement or an unexpected end offset
is refused. Core chooses deadlines and explicitly retries the same
packet; neither the OS shell nor the framing codec starts a retry timer.

The receiver keeps one bounded piece buffer. It accepts contiguous bytes
and identical duplicates, acknowledging the latter again without
appending. A gap, changed length or conflicting duplicate is refused
without appending. Before completing a piece, it MUST decode A7 and
verify the decoded index and backup hash against the packet and accepted
share. A malformed completed piece is dropped so it can start again.
A final-fragment replay MUST return the completed piece again so storage
can be retried after a lost acknowledgement. Replaying an earlier fragment
after completion MUST return only its acknowledgement, without decoding
or copying the whole piece again.

Core MUST persist a completed piece through `take_hand_back_piece`
before sending its final acknowledgement. The codec's receipt alone is
not a storage receipt. Restarting a meeting retries a piece from its
beginning; completed pieces are already persistent and idempotent. A
cancelled sender or receiver refuses further acknowledgements or data;
Core cancels the corresponding hardware operation and ignores its late
observations. A restarted attempt MUST use a fresh scoped link operation;
observations from its retired predecessor MUST NOT reach the new codec.
The acknowledgement carries no transfer identity of its own.

Acknowledgements are flow control, not authentication or proof of
restoration. The taken share, whole-backup hash, backup encryption and
restored-identity check in A11 remain the acceptance boundaries. Completing
the transport MUST NOT itself declare recovery successful.

### What ships today

`export_guardian_backup_with_shards`, `export_guardian_backup_for_groups`,
`respond_to_recovery` and `recover_guardian_backup` are Core API with
tests. Each change to the recovery-trusted contacts exports a fresh
guardian backup when there are three to nine of them
(`send_guardian_backup`; Shamir needs three shares, so one or two
guardians get none), split over the owner's groups (A2), sealed under
the owner's passphrase when one is set (A9), and queues each guardian
its sealed share with the file in A7 pieces (vauchi/private#796).
Guardians
keep the newest whole delivery (A8), forget it on a release, and hand
it back by itself after the meeting's exchange (A5). Turning on a
contact's recovery trust asks which group it joins once a group
exists. Restoring the returned backup into the new identity (A10) is
Core API with tests, and the new phone's recovery screen offers it
once a guardian has handed back; labels come back with their
members and the fields they show, and each contact with its own
visibility rules (a backup made before the labels' fields were kept
restores them showing none). The rekey offers of the restored contacts (section C, C1 to C6) are
Core API with tests and leave with each sync; no contact accepts one
yet (C3), so no rekey completes.
The guardian **tokens** of A4 do reach the relay today,
for up to nine recovery-trusted contacts. A tenth makes the set 2 050
bytes, over the relay's 2 048, and the whole set is refused without
the person being told (vauchi/private#929).

### Security considerations

- **Social recovery needs the guardians, and only the real ones**,
  claim [S17](../claims.md): `backup_needs_both_guardians` (also under
  `-DGROUP_OF_TWO` and `-DTHREE_GROUPS`, falsified under
  `-DONE_GUARDIAN`), `a_group_mate_can_stand_in`,
  `john_rekeys_only_with_the_real_alice` and
  `alice_rekeys_only_with_the_real_john` in `social_recovery.spthy`.
  The model's rekey half describes the design of section C, not the
  code.
- Fewer than `t` shares are information-theoretically useless; a
  guardian learns nothing about the file, which is public ciphertext
  under `B`. A thief with the old device has the old keys, not the
  shares.
- The relay sees who designated guardians (the hash is of the owner's
  key) and how many entries; it sees no guardian identity, since each
  token is sealed to its guardian, until a recovery proof is uploaded:
  a guardian voucher carries its token, with the guardian's key, in
  the clear.

---

## B. Recovery vouching

### Normative operations

Source: `vauchi-core/src/recovery/mod.rs`, `recovery/proofs.rs`,
`api/vauchi/recovery.rs`, `api/vauchi/recovery_offline.rs`;
`relay/src/recovery_storage.rs`.

**B1. Claim** (`RecoveryClaim`). The recovering person shows, as a QR,
`0x01 || old_pk(32) || new_pk(32) || timestamp as LE u64` (73 bytes).
The recovery window is measured on the vouchers, not on the claim: the
vouchers in a proof MUST span at most 96 h (B4). A helper sees only
the claim, never the vouchers already given, so its own bound is
looser: it MUST refuse a claim older than 192 h (`MAX_AGE_SECS`), and
a claim stamped more than 10 minutes ahead of its own clock
(`MAX_FUTURE_SKEW_SECS`, `TimestampInFuture`): further ahead is a
forgery that would stretch every age bound, not a slow clock
(maintainer, 2026-10-31). A
recovery that starts late gets less than 96 h, and a recovering device
MAY drop its oldest vouchers to keep the rest inside the span. The
parser takes exactly 73 bytes and never panics
(`recovery_claim_parse_never_panics_and_reads_each_field_at_its_offset`);
Kani proves the same of a contact voucher and a guardian token (by
hand: 54 minutes for the token, past the CI caps), and in CI that the
age and skew bounds are exact with no overflow
(`recovery_voucher_parse_accepts_exactly_a_contact_voucher`,
`guardian_token_parse_accepts_exactly_one_token`,
`recovery_time_bounds_are_exact_and_never_overflow`, vauchi/private#937).

A recovering device keeps one claim in progress. Showing the same
`old_pk` again MUST resume that claim and its vouchers while the claim
is younger than 192 h, and MUST NOT replace it with a fresh claim
unless the person confirms; past that it offers a fresh claim.

**B2. Voucher** (`vouch_for_claim`, `RecoveryVoucher`). A helper MUST
vouch only for a claim whose `old_pk` is one of its contacts
(vauchi/private#708) and MUST refuse to vouch with the claim's own old
or new key (`SelfVouching`). The voucher is Ed25519 by the helper over
`"vauchi-recovery-voucher-v1" || old_pk || new_pk || helper_pk ||
timestamp as LE u64`, serialized as

```text
0x01 || old_pk || new_pk || helper_pk || timestamp || signature(64)          contact voucher
0x03 || ... same ... || token_len as LE u32 || GuardianToken                 guardian voucher
```

A guardian voucher's signature is over the same fields followed by the
token's postcard bytes, so a token cannot be stripped, swapped or added
after signing; format 2, which carried the token outside the signature,
is refused (maintainer, 2026-10-31, vauchi/private#930). A parser takes
exactly the header, or the header, the length and that many token bytes.
A guardian helper vouching in person attaches the token from the
delivery it keeps for the claim's `old_pk` (A7), when the token
verifies and names that designator and this helper
(`create_voucher_from_claim_b64`). Over the relay, a guardian helper
opens its token from the relay set (A4), takes only
an entry whose token names the claim's `old_pk` as designator and
itself as guardian, and attaches it; the recovering device checks the
same when it adds the voucher (B3). The token is signed by the old key,
which the thief holds: a token proves nothing against the thief, it is
not authentication, and no decision reads it.

**B3. Proof** (`RecoveryProof`, `RecoveryProgress`). The recovering
person collects vouchers until the threshold (default 3, 1 to 9) is
met. Adding a voucher, while collecting as when building the proof,
MUST refuse mismatched keys, a self-voucher by
the old or new key (vauchi/private#797), a bad signature, a bad or
misaddressed guardian token, and a second voucher from the same key.
Validating a proof re-runs those checks on every voucher, bounds the
threshold to 1 to 9, and at a clock refuses a voucher stamped more
than 10 minutes ahead (B1). The proof parser takes exactly its postcard
bytes and only version 2 (vauchi/private#930).
The proof is uploaded sealed to the old key (vauchi/private#936):
version byte 3, then `new_pk` in the clear, then the postcard proof
(version 2: `old_pk`, `new_pk`, threshold, vouchers, times) encrypted
with XChaCha20-Poly1305 under `HKDF(old_pk, "Vauchi_RecoveryProof_v3")`
with those 33 header bytes as associated data, so a header moved onto
another body fails the tag. Whoever holds `old_pk`, that is the
person's contacts and a thief of the old device, opens it; the relay
and anyone else learn the new key and nothing of the helpers. It is
stored under `SHA-256(old_pk)` with an owner signature by the new
identity over `"recovery-store" || key_hash || SHA-256(sealed proof)
|| timestamp as BE u64`, which the relay verifies within 60 s against
the `owner_pk` sent with it. The relay reads the 33-byte header and
refuses an upload whose version byte is not 3, whose `owner_pk` is not
the header's `new_pk`, or that carries no signature
(vauchi/private#927); it cannot check which old key a proof belongs
to, and a proof filed under the wrong hash simply fails to open at the
contact. A proof pasted between people out of band stays the plain
postcard, which a reader tells apart by its first byte. The sealed
form has a vector (`recovery_proof`,
[Test Vectors](../vectors.md)). The relay keeps one proof per owner under a hash, at
most four owners, each replaced only by its own key; a fifth owner is
refused with `429` until a slot expires. Proofs are at most 4 KiB and
are kept 9 days from their last upload, a day past the 192 h a contact
accepts vouchers (B4). Store and query are rate-limited at 10 per
minute per hash, taken lowercase, in separate buckets; a query answers
at most 50 hashes and returns every live proof under each. Core
defines a revocation signed by the **old** key (`RecoveryRevocation`)
and a client-side `RecoveryConflict::detect`; the revocation is not
wired (no route carries it), and no shipped screen queries proofs, so
conflict detection has its data but no caller.

**B4. Verdict** (`verify_for_contact`). A contact MUST refuse a proof
whose voucher timestamps span more than 96 h, or whose earliest voucher
is more than 192 h old: the recovery is one window of 192 h in which
the person collects vouchers, restores the backup and tells contacts
about the new key (maintainer, 2026-10-30; rekeys may take longer).
Both bounds read the vouchers' timestamps because each is signed by a
different helper; the proof's own `created_at` and `expires_at` are set
by the recovering identity alone.
Otherwise the contact counts the vouchers signed by its own contacts,
excluding the claim's old and new keys: at least the verification
threshold (default 2, never above the recovery threshold) is **high
confidence**, one or
more is **medium**, none is **low**. The verdict is advice to the
person; `Contact::accept_recovery` would replace the key and overwrite
the shared key with the one it is given (no rekey produces one yet,
C), and sets the flag that makes the trust level
`Cautious` until the fingerprint is re-verified.

### What ships today

The claim, voucher, proof, upload and verdict are Core API with tests;
no shipped screen fetches proofs from the relay or calls
`verify_recovery_proof`, and no API path calls `accept_recovery`
(vauchi/private#796: "recovery stops at a confidence verdict"). The
app's claim-review engine renders the vouching and acceptance screens
from a verdict handed to it.

Defects against B1 to B4, on Core `a9a911b0a`, cli and relay `main`
of 2026-10-30:

- A helper refuses a claim after 48 h counted from the claim; entering
  the old key again replaces the claim in progress and drops its
  vouchers, and the app never resumes it (vauchi/private#919). Until
  this lands, helpers on the older code keep refusing claims past
  48 h.
- A contact's check reads no time at all: `validate` and
  `verify_for_contact` take no clock (vauchi/private#926).

### Security considerations

- **Accepting a recovery needs the real recovery**, claim
  [S16](../claims.md), partial: `accept_needs_the_real_recovery`,
  falsified under `-DNO_LOST_KEY_CHECK` (the pre-#797 code, where the
  stolen device and one corrupted helper sufficed), and
  `john_key_secrecy`, both in `recovery_acceptance.spthy`. They hold
  for an attacker who corrupts fewer than two of the helpers a contact
  counts; `john_key_secrecy` also excepts a corrupted new identity.
  Partial because the step after acceptance, giving the contact a key
  bound to the recovered identity, is not built (C).
- A voucher binds the claim's new key, so a photographed claim earns
  whoever shows it vouchers only for the key it names. The in-person
  step is what authenticates the person behind that key, and the
  helper's own contact check (#708) stops a stranger's claim about an
  unknown key.
- The 96 h span is measured on the helpers' own clocks. A helper with
  a wrong clock can push a proof outside the window, or stretch it by
  its error; one helper alone cannot move another helper's timestamp.
- The relay learns that a recovery exists under `SHA-256(old_pk)` and
  the new key that owns the slot; the old key, the vouchers' keys and
  guardian tokens are sealed to the old key (vauchi/private#936).
  Whoever knows the old key opens the proof, and a relay may have seen
  it elsewhere (guardian-store `designator_pk`, account deletion). The
  hash is stable for the slot's life, so the relay links every query
  for one recovery; a daily rotation is vauchi/private#998.

---

## C. After recovery: the old contacts

This section is compromise rotation: moving contacts to a new identity
after a device holding the identity's keys was stolen unlocked
(vauchi/private#796 P29). An ordinary recovery (A11, the password
backup, a linked device) restores the same identity and rekeys nothing.
The rotation is being redesigned around a next identity registered in
advance with policy guardians, a certificate for online contacts and
recognition for contacts met in person (vauchi/private#796, P25, P26,
P31); until the certificate exists, C3 accepts nothing. Planned, not
built (no next identity is registered today): in person, a contact
that recognizes the owner MAY rotate to the identity the owner shows only when
that identity matches the hash of the registered next identity the
contact pinned: the thief cannot produce it, and since it is fixed in
advance two meetings cannot give two successors. An identity that does
not match makes a separate contact, and the old one does not move.

The Tamarin models below allow a single recovery (`restriction Once`), so
their lemmas say nothing about two attempts competing for one old
identity; that the guardians' decision has one outcome is modelled
separately in Quint (`guardian_voting.qnt`, an inductive proof for five
guardians, three ballots and two values; `guardian_history.qnt`, traces)
and is not built.

Restoring the guardian backup gives the owner every contact with its
old shared key; the thief holds the same keys. `social_recovery.spthy`
and `recovery_acceptance.spthy` specify the rekey that must follow: the
new identity signs a fresh exchange key
(`"vauchi-recovery-rekey-offer"`) to each contact's mailbox; a contact
answers only for a key its accepted proof names, signing with its
identity key and naming the new identity it answers; the owner checks
the answer against the contact's key from the backup. With those two
checks the lemmas hold although the thief holds every old shared key:
`john_rekeys_only_with_the_real_alice` (falsified under
`-DNO_PROOF_CHECK`), `alice_rekeys_only_with_the_real_john` (falsified
under `-DNO_ANSWER_SIGNATURE` and `-DUNBOUND_ANSWER`),
`new_key_secrecy`. Remotely, a recovering user who lost every contact
cannot tell an old contact from a stranger
(`a_stranger_can_rekey_with_the_recovering_user`); only the contact's
side is protected, or a new in-person exchange (`-DIN_PERSON`,
`alice_rekeys_only_with_an_accepting_contact`).

**C1. Rekey offer** (`RekeyOffer`, `recovery/rekey.rs`). For each
contact restored from the guardian backup (A10) the new identity makes a
fresh X25519 exchange key `g^a`, kept encrypted at rest, and sends

```text
"VRK1" || new_pk(32) || g^a(32) || sig(64) || proof_len(u32 BE) || proof
sig = Ed25519(new_sk, "vauchi-recovery-rekey-offer" || new_pk || g^a)
```

with its sealed recovery proof (B3, at most 16 KiB), which it keeps once
its vouchers complete it. The new identity has the contact's old shared
key and key from the backup but no ratchet with it, so the offer goes to
`token(old shared key, contact key, day)`, the mailbox the contact
already polls for the old relationship (`rekey_offer_deliveries`). It
goes again a day after the last send, with the same `g^a`, until
answered and for at most 14 days after the restore; never before a
proof exists, never to a contact met again in person (C5), and never
from a duress session.

**C2. Rekey answer** (`RekeyAnswer`). A contact that accepted the
offer (C3) answers with its own exchange key `g^j`:

```text
"VRK2" || contact_pk(32) || g^j(32) || g^a(32) || sig(64)
sig = Ed25519(contact_sk, "vauchi-recovery-rekey-answer" || contact_pk || g^j || g^a)
```

The owner MUST accept an answer only when `contact_pk` is the contact's
key from the backup and `g^a` the offer's. Both derive the new shared key
as HKDF-SHA256 of the X25519 secret, salted with `new_pk || contact_pk`
(`rekey_shared_key`); the old shared key takes no part.

A thief holding the old device has the old shared keys, so it can
compute these mailboxes and drain them (a relay fetch deletes). That
delays a rekey; it can neither forge one nor learn the new key.

**C3. Accepting** (`take_rekey_offer`, `take_rekey_offer_authorized`).
The contact is not asked. Its device MUST accept an offer only with a
`RecoveryAuthorization` for it, and only the policy guardians' decision
certificate will grant one (design P15, P18; vauchi/private#796). That
certificate does not exist yet, so every offer MUST be dropped without a
trace. Vouchers, guardian tokens (B2, A7) and old-key signatures
authorize nothing: a thief holding the old device signs tokens and
continuations, and two legitimate attempts (a new phone lost
mid-recovery, then another) could each gather a contact's own vouchers,
so two contacts would follow different successors. Exactly one successor
per predecessor is a hard requirement (security review, 2026-11-03).

With an authorization the device MUST still check that

- the new identity signed the offer, and it is the authorized one;
- the authorized old key is an exchanged, unblocked contact's.

Every offer is dropped in a duress session. On accepting it answers to
`token(old shared key, new_pk, day)`, the mailbox the new phone polls,
and in one transaction moves the contact to the new key's id with
everything that names it, switches it to the new key and shared key,
and starts a fresh ratchet as responder on `g^j`. The answer goes again
after a day, for at most 14 days, and stops at the first message on the
new relationship.

**C4. Fold** (`fold_contact_into`, D21). When the contact already has
one for the new key, because they met in person, the old contact folds
into it instead of moving, and nothing is answered: the new contact
keeps its key, shared key, ratchet, card and the choices of its
exchange; the owner's notes, nickname and custom avatar fill in where it
has none; favorite, proposal trust and the guardian role stay set when
either had them; every other reference moves where the new contact has
no row of its own, and the rest goes with the old contact.

**C5. Continuation** (`RecoveryContinuation`, D20), withdrawn. The kind
`0x0e` (Update and Sync, B5) carries

```text
old_pk(32) || new_pk(32) || sig(64)
sig = Ed25519(old_sk, "vauchi-recovery-continue-v1" || old_pk || new_pk)
```

signed with the old key. Only the old key authorizes it, and a thief
holding the old device can meet the contact in person under a fresh
identity, so a receiver MUST decode it and change nothing; the new
phone sends none. A contact met again in person is offered the rekey
like any other and folds (C4) only on an offer C3 accepts. An in-person
exchange of a contact restored and waiting takes the exchange's shared
key and ratchet: the one exception to a repeat exchange keeping its
keys (In-Person Exchange, A8). The contact's key does not change there,
so it moves no identity.

**C6. Completing** (`take_rekey_answer`). The new phone takes an
answer only for a contact still waiting, when the contact's key from
the backup signed it and it names the exchange key it offered; it then
switches the contact to the shared key both derive, with a fresh ratchet
it starts as initiator, ends the wait and sends its card. Offers stop 14
days after the restore; a contact that has not answered by then stays
waiting.

What does exist: the recovering user's **identity revocation**,
`"vauchi-account-revoked-v1" || sender_pk || recipient_pk || timestamp`
signed by the old key and sent to each contact's mailbox
(`broadcast_identity_revocations`); the contact verifies it, destroys
the contact's CEK, deletes the contact and records a tombstone that
refuses the old key's future updates. The tombstone keeps the key (it
is the row's id) and the contact's name, encrypted at rest, and the
vouch check (B2) accepts it: a thief holding the old device can send
this revocation to every contact, and without the tombstone no one
could vouch for the real owner's recovery (vauchi/private#935). It is
the deletion path's message (Keys and Cards, C3), usable after a
recovery only while the old key is still in the owner's hands.

## State machine

Owner: `designated` (tokens on the relay) → `lost` → `claim shown` →
vouchers 0..t → `proof uploaded` → `backup restored` (A6) → old
contacts pending rekey (C, open). Guardian: `holds share` → `vouched
and re-sealed`. Contact (Core API only; no shipped screen reaches it yet): proof seen → verdict shown → `accept`,
`reject` or `remind later` (`RecoveryResponse`, saved per claim and
contact, with a reminder time the shell supplies; the 7-day
`RecoveryReminder` default is not on this path).

## Failure cases

- Claim older than 192 h, helper not a contact of the old key: refused
  by the helper before vouching. Self-voucher, duplicate helper, bad
  signature: refused when the voucher is added and again when the
  proof is validated.
- Vouchers spanning more than 96 h, or an earliest voucher older than
  192 h: the contact refuses the proof; the person starts a fresh
  claim.
- Fewer than `t` matching shares, or every subset failing the key
  confirmation: `DecryptionFailed`, nothing restored.
- Guardian set older than 365 days or proof older than 9 days: gone
  from the relay; guardians re-upload by designating again, the person
  re-uploads the proof.
- Rate limit on the relay's recovery routes: `429` on the direct
  routes, an in-band `rate limit exceeded` error over OHTTP; retry
  later.

## Vectors

None. Candidates: a Shamir split and reconstruction of a known key, a
sealed box with a fixed ephemeral key, a voucher and a guardian token
with their signing messages.

## Sources

- `vauchi-core/src/crypto/shamir.rs`, `shamir_proofs.rs`;
  `backup/key_shard.rs`, `guardian_groups.rs`, `guardian_recovery.rs`,
  `full_backup.rs`
- `vauchi-core/src/recovery/mod.rs`, `guardian.rs`, `sealed_box.rs`,
  `proofs.rs`; `crypto/signing.rs` (`to_x25519_secret`)
- `vauchi-core/src/api/vauchi/identity.rs`, `recovery.rs`,
  `recovery_offline.rs`; `network/revocation.rs`
- `relay/src/guardian_storage.rs`, `recovery_storage.rs`,
  `handler/verify.rs`, `http_api.rs`
- `vauchi-core/verification/social_recovery.spthy`,
  `recovery_acceptance.spthy`
- vauchi/private#796 and its plan; ADR-002 amendment (identity-key
  reuse for the sealed box)
