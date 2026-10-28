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
- **Guardians**: contacts holding a sealed share; one to nine, in
  groups of one to three members.
- **Helpers**: contacts who vouch in person that the old and new keys
  are the same person; a guardian can be one.
- **Contact** (John): decides whether to accept the recovery.
- **Thief**: holds the old device, with its identity key and every
  shared key on it.
- **Relay**: stores sealed guardian entries and recovery proofs it
  cannot read; the attacker of both models owns it and the network.

---

## A. Guardian backup

### Message flow

```text
Owner                                   Guardian G_i                 Relay
  | B = random 32 B; file = v5 backup under B (Keys and Cards, D4)
  | shares = Shamir(B, t, n); share_i sealed to G_i's X25519 key
  |-- sealed share_i (in person or any channel) -->|
  | token_i = sign_owner("vauchi-recovery-guardian-v1" || owner || G_i || t)
  |-- guardian set { seal(token_i) }, signed store ----------------------->| under SHA-256(owner_pk || "guardians")
  ...device lost; new identity N...
  | claim = (old_pk, new_pk, t)  shown as QR                          |
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
Kani harnesses cover the field arithmetic and interpolation
(`interpolation_never_panics_and_refuses_a_zero_or_repeated_x`,
`recover_byte_never_panics`,
`reconstruct_refuses_more_shares_than_guardians`).

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
ephemeral_pk(32) || nonce(24) || XChaCha20-Poly1305(HKDF(X25519(e, pk), "vauchi-sealed-box-v1"), shard)
```

with a fresh ephemeral key per seal, so the sender is anonymous; a
small-order recipient key MUST be refused (`WeakKey`). A sealed shard
is exactly `32 + 24 + 51 + 16` bytes.

**A4. Guardian designation** (`GuardianToken`,
`upload_guardian_entries`). For each contact marked recovery-trusted
the owner signs a token over `"vauchi-recovery-guardian-v1" ||
owner_pk || guardian_pk || created_at as LE u64`, seals it to that
guardian (A3), and stores the set on the relay under
`SHA-256(owner_pk || "guardians")` with a request signed over
`"guardian-store" || owner_pk || hash || timestamp as BE u64`; an
empty set is a signed `"guardian-delete"`. The relay MUST verify the
signature, the hash binding and a timestamp within 60 s, keep at most
10 entries of at most 256 bytes and 2 048 bytes in all, expire the set
after 365 days, and answer a query for any hash with the sealed
entries: the hash is public and the entries are opaque.

**A5. Response** (`respond_to_recovery`). A guardian opens its share
with its own X25519 secret and re-seals it to the recovering
identity's key (A3 again). Nothing of the share is shown or leaves the
device in the clear.

**A6. Restore** (`recover_guardian_backup`, `recover_from_shards`).
The recovering identity opens each re-sealed response with its own
secret, keeps those whose metadata matches the file's header, at most
`n + 1` distinct ones out of at most 18 responses, and tries
threshold-sized subsets in order: a candidate key is checked against
the file's 16-byte key confirmation (Keys and Cards, D4) before the
AEAD open, so at most 462 subsets are tried in the worst 5-of-10 case.
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
steps 1 to 3). The guardian **tokens** of A4 do reach the relay today.

### Security considerations

- **Social recovery needs the guardians, and only the real ones**,
  claim [S17](../claims.md): `backup_needs_both_guardians` (also under
  `-DGROUP_OF_TWO` and `-DTHREE_GROUPS`, falsified under
  `-DONE_GUARDIAN`), `a_group_mate_can_stand_in`,
  `john_rekeys_only_with_the_real_john` and
  `alice_rekeys_only_with_the_real_john` in `social_recovery.spthy`.
  The model's rekey half describes the design of section C, not the
  code.
- Fewer than `t` shares are information-theoretically useless; a
  guardian learns nothing about the file, which is public ciphertext
  under `B`. A thief with the old device has the old keys, not the
  shares.
- The relay sees who designated guardians (the hash is of the owner's
  key) and how many entries; it sees no guardian identity, since each
  token is sealed to its guardian.

---

## B. Recovery vouching

### Normative operations

Source: `vauchi-core/src/recovery/mod.rs`, `recovery/proofs.rs`,
`api/vauchi/recovery.rs`, `api/vauchi/recovery_offline.rs`;
`relay/src/recovery_storage.rs`.

**B1. Claim** (`RecoveryClaim`). The recovering person shows, as a QR,
`0x01 || old_pk(32) || new_pk(32) || timestamp as LE u64` (73 bytes).
A claim MUST be refused after 48 h (`MAX_AGE_SECS`). The parser never
panics (`recovery_claim_parse_never_panics_and_reads_each_field_at_its_offset`).

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
it; the token is checked to name the claim's `old_pk` as designator
and the helper as guardian.

**B3. Proof** (`RecoveryProof`, `RecoveryProgress`). The recovering
person collects vouchers until the threshold (default 3, 1 to 9) is
met. Adding a voucher MUST refuse mismatched keys, a self-voucher by
the old or new key (vauchi/private#797), a bad signature, a bad or
misaddressed guardian token, and a second voucher from the same key.
The proof (postcard, version 2) is uploaded under `SHA-256(old_pk)`
with an owner signature by the new identity over `"recovery-store" ||
key_hash || SHA-256(proof) || timestamp`; the relay keeps proofs of at
most 4 KiB for 90 days, rate-limits store and query at 10 per minute
per hash, and answers a query of at most 50 hashes. A revocation
signed by the **old** key (`RecoveryRevocation`) can cancel a recovery
it names; conflicting proofs for one old key are detectable
(`RecoveryConflict::detect`).

**B4. Verdict** (`verify_for_contact`). A contact judging a proof
counts the vouchers signed by its own contacts, excluding the claim's
old and new keys: at least the verification threshold (default 2,
never above the recovery threshold) is **high confidence**, one or
more is **medium**, none is **low**. The verdict is advice to the
person; `Contact::accept_recovery` would replace the key and discard
the shared secret, and sets the flag that makes the trust level
`Cautious` until the fingerprint is re-verified.

### What ships today

The claim, voucher, proof, upload and verdict are Core API with tests;
no shipped screen fetches proofs from the relay or calls
`verify_recovery_proof`, and no API path calls `accept_recovery`
(record `2026-10-24-recovery-acceptance-never-rekeys`, "recovery stops
at a confidence verdict"). The app's claim-review engine renders the
vouching and acceptance screens from a verdict handed to it.

### Security considerations

- **Accepting a recovery needs the real recovery**, claim
  [S16](../claims.md), partial: `accept_needs_the_real_recovery` and
  `john_key_secrecy` in `recovery_acceptance.spthy`, falsified under
  `-DNO_LOST_KEY_CHECK` (the pre-#797 code, where the stolen device
  and one corrupted helper sufficed). The lemma holds for an attacker
  who corrupts fewer than two of the helpers a contact counts.
  Partial because the step after acceptance, giving the contact a key
  bound to the recovered identity, is not built (C).
- A helper who vouches on a photographed claim within 48 h vouches for
  whoever shows it; the in-person step is the authentication, and the
  helper's own contact check (#708) stops a stranger's claim about an
  unknown key.
- The relay learns the hash of the recovering identity's old key, the
  new key inside the proof it stores, and the vouchers' keys: a
  recovery is visible metadata to the relay by design, so that
  contacts can find it.

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
refuses the old key's future updates. It is the deletion path's
message (Keys and Cards, C3), usable after a recovery only while the
old key is still in the owner's hands.

## State machine

Owner: `designated` (tokens on the relay) → `lost` → `claim shown` →
vouchers 0..t → `proof uploaded` → `backup restored` (A6) → old
contacts pending rekey (C, open). Guardian: `holds share` → `vouched
and re-sealed`. Contact: proof seen → verdict shown → `accept`,
`reject` or `remind later` (`RecoveryResponse`, saved per claim;
reminders default to 7 days).

## Failure cases

- Claim older than 48 h, helper not a contact of the old key,
  self-voucher, duplicate helper, bad signature: refused at voucher or
  proof time.
- Fewer than `t` matching shares, or every subset failing the key
  confirmation: `DecryptionFailed`, nothing restored.
- Guardian set older than 365 days or proof older than 90 days: gone
  from the relay; guardians re-upload by designating again.
- Rate limit on the relay's recovery routes: `429`, retry later.

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
- Record `2026-10-24-recovery-acceptance-never-rekeys` and its plan
  (vauchi/private#796); ADR-002 amendment (identity-key reuse for the
  sealed box)
