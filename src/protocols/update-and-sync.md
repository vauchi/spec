<!-- SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Card Update and Sync

> **Status: extracted 2026-10-28** from `vauchi/core` `612992b0b`;
> checked against core `a9a911b0a` on 2026-10-30.
> How a changed card reaches every contact (sections A to D) and every
> own device (section E), through a relay that stores what it cannot
> read. Claims backed: [S1](../claims.md), [S2](../claims.md),
> [S5](../claims.md), [S11](../claims.md); it also carries the
> client side of [S4](../claims.md), whose relay side is in
> [Relay](relay.md).

## Goal

When a person edits their card, each contact that may see the changed
fields receives exactly those changes, from that person, once, in
order, and nobody else learns what changed: not the relay, not a
network observer, not someone who later steals a device's keys. Each
of the person's own devices sees the same contacts and the same card.

## Actors

- **Sender** and **recipient**: two contacts who exchanged (any
  exchange chapter) and hold a shared key and a Double Ratchet per
  device pair.
- **Devices**: a contact may have up to ten; each gets its own copy.
- **Relay**: `vauchi/relay`, reached over Oblivious HTTP; stores blobs
  by mailbox token for up to 120 days and deletes them on
  acknowledgement.
- **Attacker**: the attacker of `card_update.spthy`: controls the relay
  and the network (withholds, reorders, replays), and may obtain a
  ratchet state or an identity key.

---

## A. Message flow

```text
Sender                                 Relay                         Recipient
  | edit own card                        |                              |
  | delta = changes since last sent,     |                              |
  |   filtered to what this contact sees |                              |
  | version = last_sent + 1; sign        |                              |
  | CEK fresh; wrap; ratchet-encrypt     |                              |
  |   (padded) once per recipient device |                              |
  | POST /v2/send                        |                              |
  |   { recipient token T_day,           |                              |
  |     ciphertext, origin_hint? }       |                              |
  |------------------------------------->| store under T_day            |
  |                                      |<-- POST /v2/fetch { tokens:  |
  |                                      |     today, yesterday, owed } |
  |                                      |--> blobs ------------------->|
  |                                      |      decrypt, check, apply   |
  |                                      |<-- ACK (relay deletes)       |
```

`T_day` is the recipient's mailbox token for the day (C1). The relay
never sees a sender identifier on this path.

---

## B. Building an update

### Normative operations

Source: `vauchi-core/src/sync/delta.rs`, `api/vauchi/sealing.rs`,
`api/vauchi/propagation.rs`, `api/vauchi/visibility.rs`,
`crypto/ratchet.rs`, `crypto/chain.rs`, `crypto/padding.rs`,
`exchange/ratchet_bootstrap.rs`.

**B1. Delta** (`CardDelta::compute`). A delta is the list of changes
between the last card sent to a contact and the current one: `Added {
field }` for a new or changed field (value or network id), `Removed {
field_id }`, `DisplayNameChanged { new_name }`. A field in a delta
MUST be stripped of private annotations (`strip_private`: the owner's
notes never leave the device). The delta carries a random 32-byte
nonce, never all zero, and the time it was made.

**B2. Visibility.** Before anything else the delta is filtered to the
fields the contact may see, by the effective visibility of
[Keys and Cards](keys-and-cards.md) G2 (`filter_with` over
`field_visible_to_contact`); a display-name change always passes. A
contact never receives a field it was not granted.

**B3. Version and signature** (`cek_wrapped_card_delta`). The version
is the contact's last sent version plus one, per contact, stamped
before signing. The signature is Ed25519 by the sender's identity over
the JSON of

```text
{ domain: "vauchi-delta-v3", version, timestamp, changes, nonce,
  sender_pk, recipient_pk }
```

(`signable_bytes`). Binding the recipient's key is what stops a signed
delta from being replayed to a different contact.

**B4. Content key wrap.** Every update carries a fresh random 32-byte
content encryption key (CEK). The signed delta's JSON is encrypted
under the CEK with tag `0x02`, and the inner payload is

```text
0x08 || cek(32) || signature(64) || nonce(32) || len(4, BE) || Enc(CEK, delta JSON)
```

(`CekWrappedPayload::encode`, `PAYLOAD_VERSION_CEK`). The recipient
stores the CEK with the card and encrypts the card under it at rest;
destroying the CEK erases that card (Keys and Cards, C1). A Kani
harness proves the decoder never panics and reads each field at its
offset (`cek_wrapped_payload_decode_never_panics_and_reads_each_field_at_its_offset`),
for inputs of at most 136 bytes. The decoder accepts bytes trailing
the `ct_len` ciphertext and ignores them (vauchi/private#949).

**B5. Inner payload versions.** The first byte of a ratchet plaintext
routes it:

| Byte | Payload | Where |
|------|---------|-------|
| `0x03` | reciprocity confirmation | In-Person Exchange, D3 |
| `0x04` | safety alert, signed, replay-protected | `sync/safety_alert.rs` |
| `0x05` | registry push | `sync/registry_activation.rs` |
| `0x06` | registry ack | `sync/registry_activation.rs` |
| `0x07` | reciprocity answer | In-Person Exchange, D3 |
| `0x08` | CEK-wrapped card delta | B4 |
| `0x09` | cover (duress) | Keys and Cards, F3 |
| `0x0a` | resync request | B9 |

A receiver MUST reject an unknown version byte. All of them travel in
the same ratchet envelope, but the padding bucket follows the
payload's length, so kinds of different sizes land in different
buckets. A genesis copy (C5) carries the header `(0, 0, 0)` with a
fresh `dh_public`.

**B6. Double Ratchet** (`DoubleRatchetState`). Each `(contact, device
pair)` has one ratchet, seeded at exchange time (`bootstrap_exchange_ratchet`,
the side with the smaller identity key is initiator):

```text
initiator: dh = fresh X25519; (root, send_chain) =
           HKDF(salt = shared_key, ikm = X25519(dh, peer_exchange_key),
                "Vauchi_Root_Ratchet", 64 bytes)
responder: root = shared_key; no sending chain until the first message
```

A message is

```text
header = dh_public(32) || dh_generation(4) || message_index(4) || previous_chain_length(4)
plaintext' = pad(plaintext)                       buckets 256/512/1024/4096, then 256-aligned
ciphertext = AEAD_0x03(message_key, plaintext'; AD = header)
```

carried as JSON `{ dh_public, dh_generation, message_index,
previous_chain_length, ciphertext }`. Chain step: `message_key =
HKDF(chain, "Vauchi_Message_Key")`, `chain' = HKDF(chain,
"Vauchi_Chain_Key")`. On a message with a new `dh_public` the receiver
MUST first derive the skipped keys of the old chain up to
`previous_chain_length`, then step: `(root, recv) = HKDF(salt = root,
X25519(our_dh, their_new), root_info)`, generate a fresh `our_dh`,
`(root, send) = HKDF(salt = root, X25519(our_new, their_new),
root_info)`, generation plus one. Limits: at most 1 000 skipped keys
held, at most 1 000 skipped in one jump, at most 2 000 messages per
chain; beyond them the message is refused. Skipped keys have no age
limit. Decryption runs on a copy of the state, and the state is
replaced only when the tag and the padding both verify
(`test_crypto_hardening_ratchet_*_rolls_back_state`). "Padding
verifies" means only that the length prefix fits the plaintext: the
receiver never checks the bucket size (`is_valid_bucket_size` is
called only in tests, vauchi/private#946). Headers are not encrypted:
the relay sees `dh_public`, the generation and the index of every
blob (`ratchet.rs`, #229).

The ratchet MUST decrypt a message delivered out of order, including a
responder message the relay holds back until after the initiator has
started its next round. On Core `a9a911b0a` it did not: the skipped
keys of the sender's previous chain were stored under the receiver's
own generation counter, which differs from the sender's on the
responder's side (observed in a test, vauchi/private#943; fixed on
core `issue/943`, whose test is named in the issue).

**B7. One copy per device** (`encrypt_payload_for_contact_devices`).
When the contact's device registry is known and the bilateral
activation handshake (`0x05`/`0x06`) has completed, the payload is
encrypted once per active peer device under a device-pair ratchet:

```text
pair_key = HKDF(ikm = X25519(our_device_exchange, their_device_exchange) || shared_key,
                "vauchi-device-pair-ratchet-v1" || id_lo || device_lo || id_hi || device_hi)
```

with `(identity, device_id)` pairs in byte order and the smaller pair
as initiator (`bootstrap_device_pair_ratchet`). Otherwise one copy
goes through the shared session under device id `[0; 32]`. Each copy
advances its own ratchet; all are persisted in one savepoint with the
CEK and the sent version (`seal_and_persist_card_delta`).

**B8. Addressing** (`network/mailbox_token.rs`, `anonymous.rs`,
`origin_hint.rs`, `http_adapter.rs`). The recipient's mailbox for a
day is

```text
T = HKDF(shared_key, "Vauchi_Mailbox_v1" || recipient_identity_key || day as BE u64)
day = unix_seconds / 86 400
```

and, for a device-scoped copy, `HKDF(shared_key,
"Vauchi_MailboxDevice_v1" || recipient_identity_key || device_id ||
day)`. Each direction of a channel has its own token, so a party never
fetches its own sends. The HTTP send carries the token, the
base64 ciphertext of B6 and, for a device-scoped copy, an **origin
hint**: an AEAD over the sender's device id under a key derived from
the shared key, bound to the token and the ciphertext, so the receiver
can pick the right device-pair ratchet without the relay learning the
sender device. An hourly anonymous sender id `HKDF(shared_key,
"Vauchi_AnonymousSender_v2" || hour as LE u64)` exists for the legacy
WebSocket envelope; the HTTP path does not send it. A message to the
relay is at most 1 MiB (`MAX_MESSAGE_SIZE`). Every send goes to the
relay in the client's own configuration: the relay URL a contact
named in its QR is stored (In-Person Exchange A7) and carried on the
pending update as `target_relay_url`, but nothing in the sync
controller routes by it.

**B9. Resync.** A contact may send `0x0a`; the receiver answers by
repropagating its visible card, at most once per contact per day
(vauchi/private#691).

---

## C. Receiving

### Normative operations

Source: `vauchi-core/src/api/vauchi/sync_http.rs`, `send_phase.rs`,
`api/sync/card_update.rs`, `api/vauchi/receive_routing.rs`,
`network/mailbox_token.rs`, `network/relay_client.rs`.

**C1. Choosing tokens** (`register_mailbox_tokens`, `plan_receive`).
On each sync the client computes, for every contact that is not
blocked, the tokens of the days it still owes: from its last
exhaustive checkpoint minus one day (rotation skew) up to today, never
more than 120 days back (`RETAINED_DAYS`), at most 14 owed days per
cycle plus yesterday and today. Registering is local: the
`RegisterMailbox` message only fills the transport's
`registered_batches` (`http_adapter.rs`); the relay receives no
registration and learns tokens only from `/v2/fetch`. The tokens of
each day epoch form their own list, padded to a multiple of 256 with
random tokens and shuffled (`padded_registration_batches`,
`registration_batches` in `receive_context.rs`,
`batch_register_tokens_with_device_sync`), and fetched in requests of
at most 100 tokens (`MAX_FETCH_TOKENS`); a request never spans two
lists (`fetch_chunks`, core!2060).

The padding MUST hide the number of contacts and which tokens recur,
and does not (vauchi/private#946). It is drawn fresh on every sync
while the real tokens recur, so two fetches of one day's list
intersect in exactly the real tokens: across cycles the relay learns
the client's real token set and with it the number of contacts.
Keeping day epochs apart does not unlink days either: day D's tokens
are fetched again on D+1 as yesterday's, so the relay can link those
two requests.

**C2. Fetching.** `POST /v2/fetch` returns blobs for the registered
tokens, paged; the client acknowledges each blob it has processed, by
blob id and token, and the relay deletes it. A blob is attributed to a
contact by the token it arrived on (`receive_context.rs`); a blob on a
token nobody registered is dropped
(`unsolicited_tokens_are_rejected_for_immediate_fetches`,
`unattributed_blobs_are_not_delivered_or_acknowledged`). The
checkpoint advances only after an exhaustive pass.

**C3. Checks, in order** (`process_single_card_update_for_device_with_budget`):

1. The sender is not revoked and the contact is not blocked
   (`SenderRevoked`, `ContactBlocked`).
2. The ratchet for `(contact, device)` is loaded, or a device-pair
   ratchet is bootstrapped as in B7; without either, the blob is tried
   as a genesis envelope (C5).
3. The blob parses as a ratchet message and decrypts; otherwise a
   genesis attempt (rate-limited), and for a device route a session
   repair, then `DecryptionFailed`.
4. The version byte routes the payload (B5); only `0x08` continues.
5. The CEK payload decodes; an all-zero CEK is refused.
6. The delta's signature verifies with the contact's identity key as
   sender and our own as recipient (`SignatureInvalid`).
7. The nonce has not been seen from this sender (`ReplayDetected`).
8. The version is not below the last applied version from this
   `(contact, device)`: `version > 0 && version < last` is
   `StaleVersion`. The floor is per sender device because each device
   numbers from its own storage.
9. A durable per-contact map orders each field and the display name by
   `(signed timestamp, sender device id, delta version)`. Additions use
   the field's signed `updated_at`; removals and names use the delta's
   signed timestamp. Strictly older tuples are skipped. Removal stamps
   remain as tombstones even after the field disappears. Equal legacy
   tuples have no causal distinction and retain their apply semantics.
   The new CEK is stored even if all card changes were skipped.
10. Ratchet state, nonce, card, version floor and ordering state are
    written in one transaction. Failures must leave the ciphertext
    retryable without advancing the durable ratchet.

The ordering map holds at most 4096 keys per contact, including the
name. Existing keys can still change at capacity; a new distinct key
fails with `OrderingCapacityExceeded`. Tombstones are never expired to
make room. Upgrade seeds live field timestamps but cannot reconstruct
previously removed fields or a previous name's timestamp. The map
survives storage reopening and key rotation; current contact/full
backup formats do not transfer it. These are limits on rollback
protection, which also trusts the sender devices' signed clocks. A
relay that withholds an update can still delay learning the new state.
The owner's notes on removed fields are deleted before the transaction,
best effort; a failed update may therefore still delete those notes.

**C4. Blocking and receipts.** A blocked contact receives no further
updates. Its tokens are neither fetched nor accepted
(`receive_context.rs`), so its blobs never reach step 1, whose
`ContactBlocked` check is a second guard. The block is local and
synced only to the owner's own devices, never signalled to the blocked
contact (ADR-056). The client sends no delivery or read receipt of any
kind: there is no code path that would emit one, and the settings
toggle that once claimed to control delivery receipts was removed
because nothing read it (core!2056, ADR-057 addendum 2026-10-28). A
stored settings file that still carries the old flag loads and the
flag is ignored.

**C5. Genesis envelope** (`exchange/genesis.rs`, ADR-068). A device
that holds a contact's shared key but no session (a linked device
that never did the exchange) can send a signed safety alert in a
ratchet message rooted directly in the shared key
(`vauchi-genesis-root-v1`, `vauchi-genesis-responder-v1`); the
receiver opens it statelessly, verifies the inner identity signature
over both identities, the header and the alert, and persists the
alert, its nonce and the new session in one transaction. A card delta
or cover payload to a peer device whose device-pair ratchet has this
side as a responder that has not yet received also goes out this way
(`propagation.rs`). Every genesis envelope is a fresh message 1 and
the sender keeps no session from it (`persist_session: false`), so no
genesis envelope has forward secrecy.

---

## D. State machine

Per `(contact, device)` ratchet: a responder cannot send until it has
received once (`can_send`); every send or receive advances and
persists the state. Per outbound update (`storage/pending`): `Pending`
→ `Sending` → deleted by `mark_update_sent` as soon as the relay
accepts the send (`send_phase.rs`); a failed send becomes `Failed {
retry_at }` and is retried. There is no acknowledged state: delivery
rests on the relay's store-and-forward. Per receive cycle: choose
tokens → fetch pages → process → acknowledge → checkpoint when
exhausted.

---

## E. Own devices

Source: `vauchi-core/src/sync/device_sync.rs`,
`api/sync/device_orchestrator.rs`, `api/vauchi/device_sync_loop.rs`.

**E1. Items.** Changes an owner makes are journaled as `SyncItem`s
(contact added or removed, card and visibility changes, groups, tags,
trust, blocks, notes, deletion scheduling, ...) with Unix-second
timestamps. Cross-device conflicts resolve last-write-wins per key,
with timestamp ties going to the higher device id. Scheduling and
cancelling deletion share one `deletion:state` key. Old separately
persisted schedule/cancel stamps are folded into its maximum on load.
A batch holds at most 10 000 JSON entries, including metadata.

**E2. Encryption and addressing.** A batch for device `D` is encrypted
with tag `0x02` under

```text
HKDF(X25519(our_device_exchange, D_device_exchange), "Vauchi_DeviceSync")
```

(`encrypt_for_device`), a static-to-static agreement: there is no
ratchet between own devices, and a later compromise of either device's
exchange key opens every past batch. It is addressed to

```text
HKDF(seed, "Vauchi_DeviceSyncRecipient_v1" || D_device_id || day)
```

(`compute_device_sync_token`), one mailbox per device so a sibling
never drains another's copy. The legacy envelope sets `sender_id` to
the identity key in hex for these messages; the HTTP transport sends
only the token and the ciphertext.

**E3. Durable ordering.** Updated senders persist a checked, increasing
journal sequence with each pending item and the version vector in the
same transaction. Retries reuse those item sequences; acknowledging a
prefix does not discard later queued changes. Inside the encrypted
JSON array the first entry is metadata:

```json
{"_VauchiDeviceSyncOrder": {"version": 1, "sender": [0], "recipient": [0], "sequences": [1, 2]}}
```

The example abbreviates each device id; actual ids contain exactly
32 bytes. `sequences` has one slot per following raw array entry;
legacy pending entries may have `null`. Present sequences MUST be
positive and strictly increasing within the batch. The receiver MUST
validate metadata position, uniqueness, version, count and both device
ids. Malformed metadata MUST NOT be treated as a legacy batch. Unknown
items are skipped only after pairing raw positions with sequences.

The receiver retains a sequence floor per origin device and conflict
key, rather than a global origin floor that would discard a late
update to an independent field. Replays at or below that floor are
skipped. A later sequence from the same origin can replace its earlier
state within a second; other origins retain timestamp/device-id LWW.
The floor map is bounded to 10 000 keys per origin without eviction;
new keys fail at capacity. Actual application and ordering persistence
must commit together so a storage failure remains retryable.

Released tolerant readers skip the unknown metadata entry and apply
the known body items, so they do not gain the new replay protection.
Updated readers accept legacy arrays, but an unsequenced item cannot
replace a key with an ordered floor from that origin. Mixed-version
peers therefore have limited ordering guarantees. Source clocks,
backup restoration and concurrent stale cached handles require their
own analysis; sequences alone do not prove universal convergence or
freshness under arbitrary clock changes and withheld messages.

**E4. Duress.** Under a duress unlock, `record_sync_item_or_cover`
replaces an item by a cover item of the same length (Keys and Cards,
F3). About twenty other call sites journal through `record_sync_item`
with no duress check. Whether a duress session can reach any of them
is an open question (vauchi/private#947).

---

## Failure cases

- Not decryptable, wrong tag, bad padding: refused; the ratchet state
  is unchanged; a device route is repaired.
- Bad signature, wrong recipient, replayed nonce, stale version,
  unknown version byte, zero CEK: refused before any write.
- Too many skipped messages or too long a chain: refused.
- Relay unreachable: updates stay pending and retry; tokens are
  fetched again next cycle.
- Offline longer than 120 days: the relay has dropped the blobs; the
  contact's next update or a resync request restores the card.

## Security considerations

- **The relay cannot read a card or an update**, claim
  [S1](../claims.md): `changes_stay_secret` in `card_update.spthy`,
  which has no falsifying control, and the release lane case
  `integration_ohttp_relay_observations_exclude_update_content`, which
  checks only the relay's logs and metrics. What the relay does see:
  the token, the blob's bucket size, the time, the ratchet header, an
  origin-hint blob when present, and fetch requests of at most 100
  tokens (the relay refuses more), whose real subset it picks out
  across cycles (C1).
- **From the contact it claims, applied once, never rolled back**,
  claim [S2](../claims.md):
  `update_comes_from_the_sender_for_this_recipient` (falsified
  without the recipient key in the signature),
  `each_update_is_applied_once`. The `no_rollback` lemma exists only
  in the no-floor control, where it is falsified; with the floor the
  attempted induction reaches no verdict.
  This is not a formal proof of the current ordering map. Per-device
  version floors alone did not stop sibling-device rollback; C3 adds
  per-key signed ordering and tombstones, tested on both receive paths.
  Its clock, upgrade, capacity and backup limits still apply. A leaked
  identity key defeats sender authentication.
- **Sizes are padded**, claim [S5](../claims.md), partial: the buckets
  of B6 and the Kani harness
  `unpad_never_panics_and_only_accepts_a_prefixed_plaintext`, for
  inputs of at most 12 bytes; the padded token lists of C1, which do
  not hide the real tokens. Not measured against a traffic-analysis
  attacker; the ratchet header and the blob's timing are in the clear.
- **Old messages stay secret after a compromise**, claim
  [S11](../claims.md): `test_dr_forward_secrecy`,
  `test_forward_secrecy_compromised_state`,
  `test_dr_skipped_message_limit`, which never exceeds the limit. Each
  message key is deleted after use; a stolen ratchet state opens
  nothing earlier and the channel heals at the next DH step. Paths
  without forward secrecy, which the claim does not cover: every
  genesis envelope (C5), card deltas sent that way included; the
  device-pair initiator's first chain, rooted in the peer's static
  device exchange key (`bootstrap_device_pair_ratchet`); and all
  device-to-device sync (E2). Skipped keys have a count bound (1 000 per
  session) but no age limit, so the key of a withheld message stays on
  the device until the message arrives (vauchi/private#946).
- **Tokens, not keys, route**, the client side of [S4](../claims.md):
  tokens rotate daily and derive from the shared key and the
  recipient's key; the relay sees neither. The ratchet header's clear
  `dh_public` stays the same for a whole chain, so it links one
  channel's tokens across days until the next DH step (related to
  vauchi/private#229). The device-sync envelope's identity-key
  `sender_id` exists in the legacy message type and is not sent over
  HTTP; a transport that sent the whole envelope would leak it.
- **A stolen ratchet state** lets the thief deliver what they like over
  that channel until it heals, but not as the contact: the delta's
  identity signature still binds sender and recipient.

## Vectors

`ratchet` in [Test Vectors](../vectors.md): the initiator's root and
first chain from a given shared secret and DH pair, `message_key_0`,
and a message whose header is the 44-byte associated data; only
decryption is reproducible because the nonce and the padding are
random. `mailbox_tokens`: the three token derivations of B8 and E2 for
one day epoch. `x3dh` is the shared secret the ratchet is seeded from
in the relay-mediated exchange.

## Sources

- `vauchi-core/src/sync/delta.rs`, `delta_proofs.rs`,
  `sync/device_sync.rs`, `sync/safety_alert.rs`,
  `sync/registry_activation.rs`
- `vauchi-core/src/crypto/ratchet.rs`, `chain.rs`, `padding.rs`,
  `padding_proofs.rs`, `kdf.rs`
- `vauchi-core/src/api/vauchi/sealing.rs`, `propagation.rs`,
  `visibility.rs`, `features.rs`, `sync_http.rs`, `receive_context.rs`,
  `receive_routing.rs`, `resync.rs`, `device_sync_loop.rs`,
  `registry_push.rs`, `duress_cover.rs`; `api/send_phase.rs`;
  `api/sync/card_update.rs`, `registry_handshake.rs`,
  `device_orchestrator.rs`
- `vauchi-core/src/network/mailbox_token.rs`, `anonymous.rs`,
  `origin_hint.rs`, `message.rs`, `protocol.rs`, `relay_client.rs`,
  `http_adapter.rs`; `exchange/genesis.rs`, `exchange/ratchet_bootstrap.rs`
- `vauchi-core/verification/card_update.spthy`
- `vauchi/relay` `src/http_api.rs` (fetch limit)
- ADR-029 (rotating tokens), ADR-037 (OHTTP), ADR-056 (blocking),
  ADR-057 (receipts), ADR-064 (per-device routing), ADR-068 (genesis)
