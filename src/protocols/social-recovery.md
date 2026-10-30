<!-- SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

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
- **Relay**: stores sealed guardian entries it cannot read, and
  recovery proofs in the clear; the attacker of both models owns it
  and the network.

---

## A. Guardian backup

### Message flow

```text
Owner                                   Guardian G_i                 Relay
  | B = random 32 B; file = v5 backup under B (Keys and Cards, D4)
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
refusal of more shares than guardians
(`interpolation_never_panics_and_refuses_a_zero_or_repeated_x`,
`recover_byte_never_panics`,
`reconstruct_refuses_more_shares_than_guardians`); unit tests check
the field multiplication against an independent reference.

**A2. Groups** (`GuardianGroups`, vauchi/private#815). Recovery needs
one member from each group: a grouped backup is a split with
`t = n = number of groups`, and a group's share is sealed to each of
its one to three members. "All of three guardians" is three groups of
one; groups with spares are at most four; guardians number at most
nine in all. `one_member_from_each_group_recovers`,
`members_of_one_group_count_as_one`,
`a_whole_group_missing_blocks_recovery`.

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
empty set is a signed `"guardian-delete"`. The relay MUST verify the
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

**A6. Restore** (`recover_guardian_backup`, `recover_from_shards`).
The recovering identity opens each re-sealed response with its own
secret, keeps those whose metadata matches the file's header, at most
`n + 1` distinct ones out of at most 18 responses, and tries
threshold-sized subsets in order: a candidate key is checked against
the file's 16-byte key confirmation (Keys and Cards, D4) before the
AEAD open, so at most C(10, 5) = 252 subsets are tried, in the worst
case of 5 of 9 guardians.
The first key whose AEAD authenticates yields the envelope; the caller
restores it like a password backup. Responses do not authenticate
their sender, so several injected responses with the right metadata
can displace honest ones from the bounded set and deny the recovery;
they cannot make a wrong key accepted.

### What ships today

`export_guardian_backup_with_shards`, `export_guardian_backup_for_groups`,
`respond_to_recovery` and `recover_guardian_backup` are Core API with
tests; the app does not yet export a guardian backup on designation
nor move shares to guardians automatically (vauchi/private#796, plan
steps 1 to 3). The guardian **tokens** of A4 do reach the relay today,
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
looser: it MUST refuse a claim older than 192 h (`MAX_AGE_SECS`). A
recovery that starts late gets less than 96 h, and a recovering device
MAY drop its oldest vouchers to keep the rest inside the span. The
parser never panics
(`recovery_claim_parse_never_panics_and_reads_each_field_at_its_offset`).

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
0x02 || ... same ... || token_len as LE u32 || GuardianToken                 guardian voucher
```

A guardian helper opens its token from the relay set (A4) and attaches
it; the recovering device checks that the token names the claim's
`old_pk` as designator and the helper as guardian when it adds the
voucher (B3). The voucher signature does not cover the token, and the
token is signed by the old key, which the thief holds: a token proves
nothing against the thief, and no decision reads it.

**B3. Proof** (`RecoveryProof`, `RecoveryProgress`). The recovering
person collects vouchers until the threshold (default 3, 1 to 9) is
met. Adding a voucher MUST refuse mismatched keys, a self-voucher by
the old or new key (vauchi/private#797), a bad signature, a bad or
misaddressed guardian token, and a second voucher from the same key.
The proof (postcard, version 2, in the clear) is uploaded under
`SHA-256(old_pk)` with an owner signature by the new identity over
`"recovery-store" || key_hash || SHA-256(proof) || timestamp as BE
u64`, which the relay verifies within 60 s against the `owner_pk` sent
with it. The relay reads the proof's first 65 bytes, the version byte
then `old_pk` and `new_pk`, and refuses an upload whose version is not
2, whose `old_pk` does not hash to the key hash, whose `owner_pk` is
not the proof's `new_pk`, or that carries no signature
(vauchi/private#927). It keeps one proof per owner under a hash, at
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
is more than 90 days old. Both bounds read the vouchers' timestamps
because each is signed by a different helper; the proof's own
`created_at` and `expires_at` are set by the recovering identity alone.
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
- The claim and proof parsers accept trailing bytes; the proof version
  is not checked; a proof with threshold 0 validates; a claim stamped
  in the future never expires; the recovering device refuses an
  old-key voucher only at upload (vauchi/private#930).

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
- The proof is stored in the clear. The relay learns the recovering
  identity's old key (inside the proof, stored under its hash), the
  new key (owner key and proof), the vouchers' keys and, for guardian
  vouchers, their tokens: a recovery is visible metadata to the relay
  by design, so that contacts can find it.

---

## C. After recovery: the old contacts

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
`alice_rekeys_only_with_an_accepting_contact`). None of this is in the
code yet (vauchi/private#796 steps 4 to 7).

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
and re-sealed`. Contact: proof seen → verdict shown → `accept`,
`reject` or `remind later` (`RecoveryResponse`, saved per claim and
contact, with a reminder time the shell supplies; the 7-day
`RecoveryReminder` default is not on this path).

## Failure cases

- Claim older than 192 h, helper not a contact of the old key: refused
  by the helper before vouching. Self-voucher, duplicate helper, bad
  signature: refused when the voucher is added and again when the
  proof is validated.
- Vouchers spanning more than 96 h, or an earliest voucher older than
  90 days: the contact refuses the proof; the person starts a fresh
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
