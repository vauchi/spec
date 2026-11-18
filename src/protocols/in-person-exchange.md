<!-- SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# In-Person Exchange

> **Status: extracted 2026-10-28** from `vauchi/core` `612992b0b`;
> checked against `vauchi/core` `a9a911b0a` on 2026-10-30.
> Four protocols share this chapter because they share the goal and
> the reciprocity confirmation that follows: the **mutual QR exchange**
> (section A), the **Glance exchange**, one QR plus Bluetooth (section
> B), the **NFC tap** (section C) and the **multi-stage animated QR**
> of Hover and TapHoverShake (section E). Section D is the reciprocity
> confirmation they end with. Section E checked against `vauchi/core`
> `3bd09f33c` on 2026-11-18.
> Claims backed: [S6](../claims.md), [S7](../claims.md),
> [S8](../claims.md), [S18](../claims.md).

## Goal

Two people in the same place exchange contact cards and end with a
shared key bound to both identities, so that later updates (see
[Card Update and Sync](update-and-sync.md)) reach only the person
who was there. The channel the people can see or touch, a screen, a
tap, authenticates the peer; a radio, when one is used, only carries
bytes. Each side also learns whether the other side really saved the
contact.

## Actors

- **Displayer** and **scanner**: in the mutual QR exchange both
  people are both; in Glance one shows a QR and the other scans it.
- **Reader** and **tag**: the two NFC sides. The protocol is the same
  seen from either.
- **Relay**: used only after the exchange, for the reciprocity
  confirmation (D) and for the full card when the in-person channel
  carried only keys and a name.
- **Attacker**: controls every radio and network channel, can
  photograph a QR and can hold a phone in radio range; this is the
  attacker of `qr_exchange.spthy`, `ble_advertisement.spthy` and
  `reciprocity.spthy`. The attacker is not assumed to be able to put
  their own screen in front of the user's camera unnoticed.

Other in-person modes exist in the app's mode list
(`exchange/mode.rs`): *Hover* and *TapHoverShake* run the multi-stage
animated QR protocol of section E, *Bump*, *Shake* and *Magic* run the
Bluetooth handshake of section B without a QR, and *Cable* runs the
session of section A over USB or TCP. The radio-only modes and Cable
are not specified in this chapter; what section B says about a
handshake without QR pins applies to the radio-only modes. The app
offers only Glance, Hover and Link, in its picker, a remembered choice
and its fallback when a mode cannot run (`is_offered` in
`ui/exchange/mode_selection.rs`); the other modes are deferred, their
engines kept and tested but not offered.

---

## A. Mutual QR exchange

### Message flow

```text
Alice                                                   Bob
  | 1 show QR_A = sign_A(v3, id_A, eph_A, token_A, chal_A, t, name_A[, relay_A])
  |                                   2 show QR_B (same shape)
  | 3 scan QR_B  ------------------- (line of sight) -----------------> 4 scan QR_A
  | 5 "they scanned" (a tap on each screen, not a message)
  | 6 K = HKDF(X25519(eph_A, eph_B), "vauchi-x3dh-symmetric-v2" || sorted ids || sorted ephs)
  | 7 audio: each side chirps the peer's challenge, then listens
  | 8 contact saved with K; card = the QR's name until the first sync
  | 9 reciprocity confirmation (D)
```

Nothing but the two QR codes crosses between the devices before the
key exists. The audio step is a proximity check, not part of the key
agreement.

### Normative operations

Source: `vauchi-core/src/exchange/qr.rs`, `qr_url.rs`, `session.rs`,
`key_order.rs`, `ratchet_bootstrap.rs`,
`contact/reciprocity_tokens.rs`, `exchange/confirmation_escrow.rs`;
consumer `vauchi-cli/src/commands/exchange.rs`.

**A1. QR payload v3** (`ExchangeQR::generate_with_relay`,
`to_bytes`). A session MUST generate a fresh X25519 key pair
(`X3DHKeyPair::generate` in `ExchangeSession::new_qr`), a random
32-byte `exchange_token` and a random 16-byte `audio_challenge`. The
payload is

```text
"WBEX" || 0x03 || id(32) || eph(32) || token(32) || challenge(16)
|| timestamp(8, BE seconds) || name_len(2) || name || flags(1)
|| [relay_len(2) || relay_url] || signature(64)
```

`id` is the Ed25519 identity key, `eph` the fresh X25519 key, `name`
the identity's display name in UTF-8 (at most the card's character
limit, checked as 4 bytes per character before anything is allocated),
`flags` bit 0 set when a relay URL follows, bits 1 to 7 reserved. The
Ed25519 signature by `id` covers everything after the magic and before
the signature itself, the relay fields included, with one exception:
the signed flags byte is not the one received. `verify_signature`
rebuilds it from whether a relay URL was parsed, so reserved bits 1 to
7 are neither signed nor rejected (vauchi/private#949). The QR shows
`https://vauchi.app/x#q=<base64url, no padding>`; the payload rides in
the fragment, which a browser never sends to the server. A scanner
MUST also accept the older raw standard-base64 form, MUST refuse a
scan longer than 4 096 characters before decoding, a payload shorter
than 192 bytes, a magic other than `WBEX`, and any version but 3
(`InvalidQRFormat`, `InvalidProtocolVersion`).

**A2. Expiry.** A QR is valid for 300 s from its timestamp
(`QR_EXPIRY_SECONDS`); the check is `now > timestamp + 300` with the
addition checked, so a timestamp near the top of `u64` counts as
expired (`qr_timestamp_overflow_tests.rs`).

**A3. Scan** (`handle_process_qr`). The session MUST be in
`DisplayingQr`. It MUST reject an expired QR (`QRExpired`), a bad
signature (`InvalidSignature`) and a QR carrying its own identity key
(`SelfExchange`), in that order, and then record the peer's identity
key, exchange key, audio challenge, display name and relay URL. A
scanned QR reaches this step only through `from_data_string`, which
already verifies the signature at parse time, so on the scan path a
QR that is both expired and badly signed fails `InvalidSignature`
first. The
scan of the other side is not observable, so a user signal
(`TheyScannedOurQR`) moves the session on; the CLI sends it right
after the scan.

**A4. Key agreement** (`handle_perform_key_agreement`). With `ss =
X25519(eph_ours, eph_theirs)`, rejecting a non-contributory result
(`InvalidDhOutput`), both sides compute

```text
info = "vauchi-x3dh-symmetric-v2" || min(id_A, id_B) || max(id_A, id_B)
                                  || min(eph_A, eph_B) || max(eph_A, eph_B)
K    = HKDF-SHA256(salt = none, ikm = ss, info)
```

(`key_order::sorted_pair`, byte-wise order). The identity keys enter
only through `info`: they are authenticated by the QR signatures (A3),
and binding them here is what `no_misbinding` in `qr_exchange.spthy`
depends on; the model shows the lemma falsified when they are left out
(`-DNO_IDENTITY_BINDING`). Note that this is not the two-DH agreement
of `exchange/x3dh.rs` (`vauchi-x3dh-key-v2`), which the relay-mediated
exchange uses; the in-person session has fresh keys on both sides and
needs no static DH.

**A5. Confirmation material.** In the same step the session derives,
from the raw DH output `ss` (not from `K`):

```text
our_token   = HKDF(ss, "vauchi-reciprocity-confirm-v1" || id_ours)
their_token = HKDF(ss, "vauchi-reciprocity-confirm-v1" || id_theirs)
gate        = hex(SHA-256(HKDF(ss, "vauchi-confirm-escrow-gate-v1")))
slot_init   = hex(SHA-256(HKDF(ss, "vauchi-confirm-escrow-slot-init-v1")))
slot_resp   = hex(SHA-256(HKDF(ss, "vauchi-confirm-escrow-slot-resp-v1")))
```

(`derive_confirmation_tokens`, `ConfirmationEscrowKeys::derive`). The
side with the smaller identity key owns `slot_init`. `our_token` on
one side equals `their_token` on the other. Section D uses them.

**A6. Proximity.** After key agreement the session runs its proximity
verifier and, when it holds the peer's audio challenge, emits
`AudioEmitChallenge` (the peer's 16-byte challenge as FSK samples) and
`AudioListenForResponse` (5 000 ms). Exactly one side emits first: a
one-way scanner, which alone holds the peer's challenge, and in a
mutual QR, where both do, the side with the smaller identity key, as
for the escrow role
(`in_a_mutual_qr_exchange_one_side_emits_first_and_the_other_listens_first`,
vauchi/private#948). The
session does not decode audio itself; a
shell reports `ProximityCheckCompleted { confidence }`. Confidence is
one of `High` (audio or a physical channel), `Medium` (the user
confirmed by hand; `ManualConfirmationVerifier`), `Low` (a check
failed) or `Unknown`. The automatic baseline the session runs after
key agreement never lowers a confidence the shell already confirmed
(`a_confirmed_medium_proximity_is_not_lowered_by_the_key_agreement_check`).
NFC and USB sessions set `High` without a check:
the tap or the cable is the proof.

**A7. Completion** (`handle_complete_exchange`). The session MUST be in
`AwaitingCardExchange`. The contact is created with the peer's identity
key, the card the shell supplies, `K` as the shared key, the proximity
confidence, the transport and trust metrics `(transport, confidence,
timestamp)`. The contact's `exchange_timestamp` is the session clock's
time at completion, for every transport
(`a_qr_session_stores_the_exchange_timestamp`, vauchi/private#948), so
the 7-day reciprocity rule (D) counts from the exchange. The QR carries
no card: the app completes a QR exchange with a placeholder card named
after the peer's QR until their card arrives over the relay
(`qr_auto_advance_names_the_contact_after_the_peer_qr`). The relay
URL from the peer's QR is stored as the
contact's relay URL and copied onto each pending update as
`target_relay_url`, but no shipped path dispatches by it: every send
goes to the configured relay through the outer hop (Card Update and
Sync B8), and the grouping by relay URL the sync manager offers has
only a test as its caller. A peer cannot choose where our updates to
it travel. A QR carries no card, so the CLI supplies a card
holding only the QR's display name (`"New Contact"` when empty); the
full card arrives with the first synced update. A session MUST fail
with `SessionTimeout` on any event other than `Fail` more than 60 s
after it was created (`SESSION_TIMEOUT`, monotonic clock).

**A8. Ratchet** (`build_exchange_ratchet` →
`bootstrap_exchange_ratchet`). The side with the smaller identity key
is the Double Ratchet initiator, keyed off the peer's exchange key; the
other side is the responder, keyed off its own ephemeral key pair. Both
sides persist the `is_initiator` flag with the ratchet. Routing every
in-person completion through this one function is what keeps the two
sides from both becoming initiator, which produces an undecryptable
channel. A repeat exchange of a contact keeps the shared key and
ratchet of the first (private#941), except for a contact restored from
a guardian backup and waiting for its rekey, which has no ratchet on
this device: it takes the exchange's (Social Recovery, C5).

**A9. Resumption** (`resume_qr`). A shell whose "start" and "complete"
are separate processes (the CLI) MUST persist the QR and its ephemeral
secret in restricted storage and delete both after completion or
expiry. The CLI writes them to one file only its owner can read
(mode 0600) but unencrypted, and deletes it only after completion; an
expired pending QR stays on disk until the next `exchange start`
replaces it. On resume the pair is checked: valid signature, not expired,
identity key is ours, exchange key matches the secret; otherwise the
resume is refused.

### State machine

`ExchangeState` (`session.rs`): `Idle` → (`StartQR`) `DisplayingQr`
→ (`ProcessQR`) `PeerScanned` → (`TheyScannedOurQR`)
`AwaitingKeyAgreement` → (`PerformKeyAgreement`)
`AwaitingCardExchange` → (`CompleteExchange`) `Complete{contact}`.
Any event out of order is `InvalidState` and leaves the state alone;
`Fail(e)` → `Failed{e}` from anywhere; a timed-out session enters
`Failed{SessionTimeout}`. `Complete` is read once (`extract_contact`)
and the session returns to `Idle`. Nothing of the session is
persisted except what A9 names; the durable result is the contact
and its ratchet.

### Failure cases

- Malformed, oversized, wrong-version or wrong-magic QR: refused at
  parse time, nothing recorded.
- Expired QR, bad signature, own QR: `QRExpired`, `InvalidSignature`,
  `SelfExchange`; the session stays in `DisplayingQr` and the user can
  scan again.
- Small-order peer exchange key: `InvalidDhOutput`, no key derived.
- Session older than 60 s: `SessionTimeout`, terminal.
- Proximity check failed or timed out: not a failure of the exchange;
  the contact is saved with `Low` confidence and a lower trust level.
- Reciprocity not confirmed: see D; the contact is kept either way.

### Security considerations

- **What a watcher gets.** A QR is public: identity key, a fresh
  public key, a name, a relay URL, a random token and challenge. The
  key `K` needs one of the two ephemeral secrets, which never leave
  the devices, and the identity keys are bound into it, so a
  transcript of both QR codes yields no key and a key agreed with the
  wrong identity fails. This is claim [S6](../claims.md):
  `session_key_secrecy` and `no_misbinding` in `qr_exchange.spthy`,
  test `test_transcript_binding_includes_identity_keys` in
  `exchange_ceremony_tests.rs`, which holds the ephemeral key and the
  peer fixed and so isolates the identity binding.
  `test_transcript_binding_includes_ephemeral_keys` does not isolate
  anything: its two sessions differ in identity and in ephemeral key,
  so the DH already differs. The tests S6 names in
  `exchange_x3dh_tests.rs` exercise the two-DH agreement of
  `x3dh.rs`, which backs the relay-mediated exchange, not this
  derivation.
- **Forward secrecy.** Both keys are fresh per session; a later leak of
  an identity key opens no past `K`. A leak of an identity key before
  the exchange lets its holder impersonate that identity in a new
  exchange, which the model states as the exception to secrecy.
- **A photographed QR** is useless to a stranger on its own: to
  complete an exchange with Alice the stranger must also get Alice to
  scan the stranger's QR. The QR's 300-second life bounds how long a
  photograph stays scannable at all.
- **Audio** is a proximity signal that raises confidence; it is not
  authenticated and does not enter the key. The trust level shown for
  the contact follows the transport and the confidence
  ([S10](../claims.md)).
- **The card** saved at completion is a placeholder; what the user
  sees until the first sync is the name the peer put in the QR, which
  the signature covers but nobody verified.

### Vectors

`qr_symmetric` in [Test Vectors](../vectors.md): two identities and
two ephemeral keys from fixed seeds, driven through the shipped
session to the key agreement; the DH, the sorted `info` of A4, the
shared key, both confirmation tokens of A5 and the confirmation
escrow gate and slots. The QR bytes themselves are not in the vector,
since the token and audio challenge are random and do not enter the
key. The `x3dh` entry is the two-DH agreement of the relay-mediated
exchange, not this one.

---

## B. Glance: one QR, then Bluetooth

The displayer shows a QR; the scanner reads it, connects over
Bluetooth Low Energy to the device whose advertisement the QR
predicts, and the two run an encrypted four-phase handshake that
carries the full cards. The handshake is also what the radio-only
modes run, without the QR pins.

### Message flow

```text
Displayer D                                              Scanner S
  | QR_D = VOQR || 1 || 0 || id_D || x_D || token || t || sig_D
  | advertises service UUID + prefix(attempt_D), attempt_D = HKDF(token, "vauchi-ble-attempt-token-v1")
  |                                      scan QR_D: pin id_D, x_D, nonce = HKDF(token, "...oob-nonce-v1")[0..16]
  |                                      connect only to an advert whose bytes prefix attempt_D
  |<---- 1 KeyOffer(0x04, id_S, x_S, e_S, n_S, t_S, nonce) ------------- CHAR_HANDSHAKE_WRITE
  | checks id_S? x_S? nonce == required; derives SK
  |----- 2 KeyAck(0x04, id_D, x_D, e_D, n_D, c_D, t_D) ----------------> CHAR_HANDSHAKE_NOTIFY
  |----- 2 Enc(SK, card_D; AAD id_D||id_S||t_D) ----------------------> CHAR_DATA_NOTIFY (chunked)
  |                                      c_D == SHA-256(ciphertext)? derive SK, decrypt card_D
  |<---- 3 c_S = SHA-256(Enc(SK, card_S; AAD id_S||id_D||t_S)) -------- CHAR_HANDSHAKE_WRITE
  |<---- 3 Enc(SK, card_S) --------------------------------------------- CHAR_DATA_WRITE
  | c_S matches? decrypt card_S; reveal = c_D
  |----- 4 reveal ------------------------------------------------------> CHAR_HANDSHAKE_NOTIFY
  |                                      reveal == c_D? complete
  | both persist the contact with SK; the initiator then sends the reciprocity ack (D)
```

`x_*` are the two sides' X3DH exchange keys, `e_*` fresh per-session
ephemeral keys, `n_*` 16-byte nonces, `t_*` Unix timestamps, `c_*`
commitments.

### Normative operations

Source: `vauchi-core/src/exchange/oob_bootstrap.rs`,
`exchange_payload.rs`, `ble_advertisement.rs`, `ble_handshake.rs`,
`ble_payload.rs`, `ble.rs`; orchestration
`vauchi-app/src/ui/app_engine/glance.rs`,
`ui/app_engine/ble_handshake.rs`,
`orchestrator/ble_handshake_machine.rs`.

**B1. OOB bootstrap QR** (`OobBootstrapQr::generate`). The displayer
shows the shared 174-byte exchange payload under magic `VOQR`:

```text
"VOQR" || version 0x01 || flags 0x00 || id(32) || x(32) || token(32)
|| timestamp(8) || signature(64)
```

`x` is the identity's X3DH public key (`identity.x3dh_keypair()` in
`begin_glance_display`): the handshake feeds the same key into DH1, so
a scanner that pins it accepts the honest peer. `token` is random per
QR. The signature by `id` covers the first 110 bytes. The QR is shown
as `https://vauchi.app/x#q=…` and is valid for 60 s
(`OOB_EXPIRY_SECONDS`), the same window as the handshake. A parser MUST
require exactly 174 bytes and version 1; the scanner path MUST verify
the signature and the expiry before pinning anything
(`verified_from_data_string`). The Kani harness
`parse_exchange_payload_never_panics_and_reads_each_field_at_its_offset`
covers the parser for all inputs up to 176 bytes.

**B2. Values derived from the token.**

```text
oob_nonce = HKDF(token, "vauchi-glance-oob-nonce-v1")[0..16]
attempt   = HKDF(token, "vauchi-ble-attempt-token-v1")
```

(`derive_oob_nonce`, `attempt_token_from_oob`). The displayer keeps
`oob_nonce` as the value a connecting peer MUST echo (B5) and
advertises a prefix of `attempt`. The nonce can be known only to a
party that read the QR: the 174-byte payload never crosses the radio.

**B3. Advertisement and discovery.** While a Bluetooth exchange screen
is open the phone advertises the Vauchi service UUID
`a1b2c3d4-e5f6-7890-abcd-ef1234567890` together with a short service
UUID carrying the first bytes of its attempt token (two on the phones;
`advertised_token` also accepts a four-byte carrier). Outside Glance
the token is fresh random per screen entry (`fresh_attempt_token`),
never derived from a long-lived key, so a bystander cannot recognise a
device across sightings (vauchi/private#726). A scanner MUST ignore an
advertisement that does not carry the Vauchi service, that carries two
different short tokens, or that carries more than 32 UUIDs. The Glance
scanner (`handle_glance_discovery`) MUST connect only to an advertiser
whose token, at least two bytes long, is a prefix of its expected
`attempt`; it is always the initiator, and it redials at most twice
after a failed dial. The displayer never dials; it is the responder
and requires the nonce (`start_ble_handshake_as_responder`). Without a
QR, both phones advertise and scan, and `decide_ble_role` makes the
side with the smaller attempt token, compared at the advertised width,
the initiator; equal prefixes make both sides initiators, and both
dial. The glare is resolved on the identity keys when an initiator
that has sent its KeyOffer receives the peer's: the side with the
larger identity key yields to responder and resets its session
(`BleHandshakeSession::reset`), but only when the offer arrived on an
inbound link; an offer on its own outbound link is ignored
(`ble_handshake_machine.rs`).

**B4. KeyOffer** (`create_key_offer`), 137 bytes:

```text
0x04 || id_S(32) || x_S(32) || e_S(32) || n_S(16) || t_S(8, BE) || echo(16)
```

`echo` is the OOB nonce the scanner derived from the QR, or 16 zero
bytes when the session was not bootstrapped by a QR or tap. Written
to `CHAR_HANDSHAKE_WRITE` (`…ef1234567894`).

**B5. Responder on KeyOffer** (`process_key_offer`). The checks run in
this order, each before any key derivation, with constant-time
comparisons: state `Idle`; length at least 137 (`InvalidBleFormat`;
bytes past 137 are accepted and ignored, as are bytes past 153 in the
KeyAck of B7, vauchi/private#949);
version 0x04 (`InvalidProtocolVersion`); `id_S` not our own
(`SelfExchange`); `id_S` equals the pinned identity, if one is pinned
(`IdentityMismatch`); `x_S` equals the pinned exchange key, if one is
pinned (`ExchangeKeyMismatch`); `echo` equals the required nonce, if
one is required (`OobNonceMismatch`), and is not the echo of an offer
this responder already accepted, remembered across resets for the life
of the session (`OobNonceReplayed`, ADR-053 single use,
vauchi/private#892); `now - t_S ≤ 60` with saturating
subtraction, and, when a nonce is required, `now - t_D ≤ 60` on the
responder's own stamp, so the connector's unsigned `t_S` cannot reopen
a Glance QR's window (`BleExpired`, vauchi/private#948); `exchange_id = SHA-256(id_S || e_S)` not
already completed. Then the responder derives `SK` (B6), encrypts its
card with AAD `id_D || id_S || t_D`, computes `c_D = SHA-256(ciphertext)`
and answers with the 153-byte KeyAck

```text
0x04 || id_D(32) || x_D(32) || e_D(32) || n_D(16) || c_D(32) || t_D(8)
```

on `CHAR_HANDSHAKE_NOTIFY` (`…95`) and the ciphertext on
`CHAR_DATA_NOTIFY` (`…97`), chunked by the transport. It keeps `t_S`
for the AAD of the card it will receive.

**B6. Session key** (`derive_session_key`).

```text
DH1  = X25519(x_ours, x_theirs)            identity binding
DH2  = X25519(e_ours, e_theirs)            forward secrecy
salt = min(n_A, n_B) || max(n_A, n_B)
info = "vauchi-ble-handshake-v4" || min(x_A, x_B) || max(x_A, x_B)
SK   = HKDF-SHA256(salt, ikm = DH1 || DH2, info)
```

Either DH non-contributory is a failure. The info prefix is bumped
with the wire version so v4 keys cannot collide with v3 keys on equal
inputs. With the QR pins in place, `x_theirs` is the key the scanner
read off the displayer's screen, so DH1 authenticates the displayer
to the scanner; the responder's check of `x_S` against its pin is the
Glance displayer's only key-level check of the scanner, and it has no
pin for the scanner in Glance, which is why the nonce echo exists.

**B7. Initiator on KeyAck** (`process_key_ack`). Checks, in order:
state `KeyOfferSent`; `now - t_S ≤ 60` on its own offer timestamp
(`BleExpired`); length at least 153; version; `id_D` not our own;
`id_D` equals the pinned identity; `x_D` equals the pinned exchange
key; `now - t_D ≤ 60`; `c_D == SHA-256(received ciphertext)`
(`BleCommitmentMismatch`). Then it derives `SK`, decrypts the card
with AAD `id_D || id_S || t_D` (`BleDecryptionFailed`), checks the
payload's CRC16 and requires its identity key to equal `id_D`
(`IdentityMismatch`) and its exchange key to equal the KeyAck's `x_D`
(`ExchangeKeyMismatch`), then encrypts its own card with AAD `id_S || id_D || t_S`,
and sends `c_S = SHA-256(ciphertext)` on `CHAR_HANDSHAKE_WRITE` and the
ciphertext on `CHAR_DATA_WRITE` (`…96`).

**B8. Responder on the committed card** (`process_committed_payload`,
`complete_exchange`). The responder MUST verify `c_S` against the
received ciphertext before anything else, stores the ciphertext, and
replies with its own commitment `c_D` as the reveal on
`CHAR_HANDSHAKE_NOTIFY`. It then decrypts the initiator's card with
AAD `id_S || id_D || t_S`, the offer timestamp it kept in B5, checks
the CRC16 and requires the embedded identity to equal `id_S`
(`IdentityMismatch`) and the embedded exchange key to equal the
KeyOffer's `x_S` (`ExchangeKeyMismatch`) before completion.

**B9. Initiator on the reveal** (`complete_exchange`). The 32-byte
reveal MUST equal the commitment received in the KeyAck; the
initiator then completes with the card it decrypted in B7. The check
runs only when the reveal is non-empty: `complete_exchange` with an
empty reveal skips it and completes (vauchi/private#949).

**B10. Commitments.** The responder commits to its encrypted card in
the KeyAck, before the initiator has sent anything encrypted. The
initiator, however, decrypts the responder's card (B7) before it
encrypts and commits to its own, and the "reveal" of B8 is only the
KeyAck commitment the initiator already received in the clear; it
reveals nothing new. An honest app fixes each side's card when its
handshake session is created, so it does not choose its card after
reading the other's; the protocol does not enforce this, and a
modified initiator can read the responder's card before it commits to
its own. The commitment is
a plain SHA-256 of the ciphertext, whose randomness comes from the
AEAD nonce.

**B11. Card payload** (`BleCardPayload`). The plaintext is a postcard
encoding of identity key, display name, exchange key, the card's
fields as label and value pairs, an optional avatar and a CRC16 over
the content. The CRC is a sanity check; integrity comes from the AEAD.
The embedded identity and exchange key MUST equal the ones received in
the handshake (B7, B8). The handshake proves possession of the exchange
key (DH1) but not of the identity key, so binding to the intended peer
still requires identity and exchange-key pins obtained out of band:
without them a peer can store a new contact under an identity it does
not hold. It cannot rekey an existing contact (B12).
On completion the receiver rebuilds a `ContactCard`, dropping a field
or an avatar that fails validation (the avatar goes through the same
WebP normalisation as a local one, ADR-042) rather than the contact.

**B12. Persisting.** The app persists the contact with `SK` as its
shared key and seeds the Double Ratchet with
`bootstrap_exchange_ratchet` as in A8, the peer's exchange key taken
from its card payload (`apply_ble_machine_event`). This is the only
Bluetooth completion path: Core's `ExchangeSession` no longer runs a
Bluetooth exchange and refuses its Bluetooth events with
`InvalidState` (vauchi/private#893). An exchange never rekeys a
contact that already exists: a repeat exchange refreshes its card and
keeps the shared key and ratchet of the first (`save_exchanged_contact`,
vauchi/private#941), except a contact restored from a guardian backup
and waiting for its rekey, which takes the exchange's (A8, Social
Recovery C5); through the multi-stage modes it takes it only once the
peer said it saved (E8). This holds for every in-person completion
path, QR and multi-stage included.

**B13. Reciprocity over the link.** After its contact is durably
saved, the initiator sends an ack: `0x01 || AEAD(SK, our_token; AAD =
"vauchi-reciprocity-ack-v1" || id_ours || id_theirs)`, where the
tokens are derived as in A5 but from `SK`
(`store_confirmation_tokens`, `build_ack`). The receiver decrypts with
the mirrored AAD and compares the plaintext in constant time with the
token it expects (`verify_ack`): a match is `Confirmed` over the
`Ble` channel, a mismatch or an undecryptable ack leaves `Pending`.

### State machine

`BleHandshakeState` (`ble_handshake.rs`): `Idle` → initiator
`KeyOfferSent` → (`process_key_ack`) `PayloadsExchanged` →
(`complete_exchange`) `Complete`; `Idle` → responder
(`process_key_offer`) `AwaitingPayload` → (`process_committed_payload`)
`PayloadsExchanged` → `Complete`. Any failure leaves the state as it
was and the orchestrator decides; a glare loser returns to `Idle` with
a fresh ephemeral key and nonce but keeps its pins. Completed exchange
ids are cached so a replayed offer is refused. On drop the session key
and nonce are zeroised; the OOB values are public and are not. The
app clears every Glance value when the exchange screen is left.

### Failure cases

- Advert without the service, ambiguous or oversized: ignored, no
  connection.
- An advertiser the scanner did not scan: ignored.
- Wrong identity, wrong exchange key, missing or wrong nonce echo:
  `IdentityMismatch`, `ExchangeKeyMismatch`, `OobNonceMismatch`,
  before any key is derived.
- Nonce echo already spent by an accepted offer: `OobNonceReplayed`,
  likewise before any key is derived.
- Offer or ack older than 60 s, our own session older than 60 s:
  `BleExpired`.
- Commitment that does not match the ciphertext, or a reveal that
  does not match the commitment: `BleCommitmentMismatch`.
- AEAD failure or CRC failure on a card: `BleDecryptionFailed`.
- Replayed offer for a completed exchange id: refused.
- Link lost: `BleConnectionLost`; the Glance scanner redials twice.

### Security considerations

- **The scanner connects to the device it scanned.** The expected
  advertisement is a function of the QR's random token, so an honest
  advertiser the scanner connects to displayed the very QR the scanner
  read. This is claim [S8](../claims.md), lemma
  `scanner_connects_to_the_displayer_it_scanned` in
  `ble_advertisement.spthy`, falsified under `-DNO_SCAN_BINDING`. The
  prefix on the air is two bytes, so a nearby device can put a
  photographed QR's prefix on the air; such a twin cannot finish,
  because the handshake pins the displayer's identity and exchange key
  from the QR (`test_pinned_initiator_rejects_key_ack_from_unexpected_identity`,
  `…_with_wrong_exchange_key` in `ble_handshake_tests.rs`).
- **The displayer's assurance is weaker.** The displayer has nothing
  to pin; it requires the nonce echo, which proves the connector read
  the QR (`test_responder_rejects_wrong_oob_nonce_echo`). The echo
  travels in the clear in the KeyOffer, so a radio observer of a
  legitimate offer could replay it; ADR-053 requires single-use nonces,
  and the displayer refuses a second offer echoing the nonce it already
  accepted, across resets, for the life of the session
  (`a_second_key_offer_with_the_same_echo_is_refused`,
  vauchi/private#892). Until that first offer it accepts any offer with
  the right echo while its exchange screen is up: the app generates the QR and
  its nonce once per screen entry and clears them on exit, and it
  refuses any offer once its own session is older than 60 s, whatever
  `t_S` the connector chose, so the QR's window closes on both sides
  (`a_glance_displayer_refuses_an_offer_after_its_own_sixty_second_window`,
  vauchi/private#948).
- **The displayer does not bind the scanner.** `ble_handshake.spthy`
  states this as `displayer_binds_the_scanner` and finds it falsified:
  a party that echoes the nonce is accepted under any identity, and the
  lemma stays falsified under `-DQR_PRIVATE`, since relaying the
  scanner's unsigned offer is enough. CI expects both falsifications in
  the extended set (`ci/formal-verification.sh`), which runs on the
  scheduled main pipeline.
- **Unlinkable advertisements.** A token derived from the identity key,
  as before #726, let a bystander recognise a phone across sightings;
  the diff-mode lemma of `ble_advertisement.spthy` shows one device
  seen twice indistinguishable from two devices seen once with random
  tokens, and distinguishable with key-derived ones. Once connected,
  however, the KeyOffer and KeyAck carry both identity keys in the
  clear: a radio observer within range of an exchange learns who met.
- **Radio-only modes** (Bump, Shake, Magic) run this handshake with no
  pins. The key is then authenticated by nothing the user saw: a
  device in radio range that wins the tiebreak can complete the
  handshake, and the mode's proximity signal is what separates the
  intended peer from an interloper. S8 does not cover them.
- **Session key.** `SK` mixes a static DH with an ephemeral DH
  (forward secrecy); nonces of both sides salt it and the version
  string separates it from every earlier wire version. DH1 binds the
  X3DH exchange keys only. The Ed25519 identity keys never enter the
  derivation: they appear in the AAD as labels nobody signs. The AAD
  ties each ciphertext to those labels and the sender's timestamp, so
  a card cannot be redirected or replayed into another session.
- **Identity binding.** The card's identity and exchange key are
  checked against the handshake's before persistence, so a card cannot
  change either after the handshake, and no exchange rekeys an existing
  contact. Without out-of-band pins the handshake still does not prove
  ownership of the wire identity: an unpinned peer can create a new
  contact under an identity it does not hold (vauchi/private#941).
- **Confirmation over the link** is authenticated by `SK` alone (B13):
  whoever holds `SK` can produce the peer's token. On this channel that
  is the two devices, or an attacker who already broke the handshake.

### Vectors

None yet. Candidates: the OOB nonce and attempt-token derivations from
one token, a KeyOffer and KeyAck with the session-key derivation of B6,
and a reciprocity ack.

---

## C. NFC tap

### Message flow

```text
Reader R                                                  Tag T
  |----- 1 offer_R = VNFC || 1 || 0 || id_R || e_R || xid || t_R || sig_R -->
  |                              verify sig, expiry, not self, xid new; K = (C3)
  |<---- 2 offer_T (same shape, same xid? no: T's own token) + Enc(K, card_T; AAD id_T||id_R||xid)
  | verify; K; decrypt card_T
  |----- 3 Enc(K, card_R; AAD id_R||id_T||xid) ----------------------------->
  |                                                        decrypt; Complete
  | Complete once the send is confirmed
```

`xid` is the exchange id: the random token of the reader's offer. Over
the air the three messages are carried as ISO-DEP APDUs with chaining
(`nfc_apdu*.rs`), not specified here.

### Normative operations

Source: `vauchi-core/src/exchange/nfc_active.rs`, `nfc_handshake.rs`,
`nfc_card_payload.rs`, `exchange_payload.rs`.

**C1. Offer and ack** (`ExchangeNfc::generate`). Both are the 174-byte
exchange payload under magic `VNFC`, version 1, with a fresh X25519
key per session (`NfcHandshakeSession::new_initiator`, also used for
the responder), a random 32-byte token and the current time, signed
by the identity key. A payload MUST be refused when older than 60 s
(`NFC_EXPIRY_SECONDS`, saturating subtraction, `NfcExpired`) or when
its signature fails (`InvalidSignature`); `verify_peer_payload` is the
single gate and MUST run before any key derivation.

**C2. Phases** (`process_key_offer`, `process_key_ack`,
`process_encrypted_card`, `confirm_send_success`). The tag, on an
offer: verify (C1); refuse its own identity (`SelfExchange`); refuse a
token already completed; derive `K`; reply with its own offer and its
encrypted card. The reader, on the ack: verify; refuse its own
identity; derive `K`; decrypt the tag's card; send its own encrypted
card. The tag decrypts and is `Complete`; the reader is `Complete`
when the shell confirms the send. If the tap drops after the key
exists, either side may enter `RelayFallback` with the exchange id and
`K` (`enter_relay_fallback`).

**C3. Key** (`derive_symmetric_key`, `build_hkdf_info`).

```text
ss   = X25519(e_ours, e_theirs)
pair = id || e, for each side; the two pairs sorted byte-wise
info = "vauchi-nfc-handshake-v1" || pair_lo || pair_hi || xid
K    = HKDF-SHA256(salt = none, ikm = ss, info)
```

As in A4, the identity keys are authenticated by the signatures of C1
and bound into `info`; the exchange id makes the key specific to one
tap.

**C4. Card** (`encrypt_card`, `decrypt_and_validate_card`). The
plaintext is an `NfcCardPayload`: identity key, display name, exchange
key and a CRC16. AAD is `sender_id || receiver_id || xid`, so a card
decrypts only for the pair and tap it was made for. An AEAD failure is
`NfcDecryptionFailed`, an unparsable payload `SerializationFailed`,
and a CRC failure after a successful decryption
`NfcCrcMismatch`. After those checks the embedded identity and exchange
key MUST match the signed NFC offer or ack (`IdentityMismatch`,
`ExchangeKeyMismatch`). NFC carries keys and a name; the full card arrives
with the first synced update, as in A7.

**C5. Trust.** An NFC exchange records proximity `High` and the
transport's proximity class `Physical`, which makes the contact's trust
level `High` without any further check (`Contact::trust_level`,
`TransportProximity::is_strong`). The level assumes the tap was not
relayed (security considerations below).

### State machine

`NfcHandshakeState`: `Idle` → reader `KeyOfferSent` → `PayloadSent`
→ `Complete`; `Idle` → tag `KeyAckReceived` → `Complete`; from
`KeyAckReceived` or `PayloadSent` `RelayFallback`; `Failed{reason}`.
`enter_relay_fallback` also accepts `KeyOfferSent`, but the reader has
no key there yet, so it fails with `InvalidState`.
Completed exchange ids are cached per session.

### Failure cases

- Wrong magic, length under 174 bytes, version other than 1:
  `InvalidNfcFormat`, `InvalidProtocolVersion`.
- Expired or unsigned payload, own identity: `NfcExpired`,
  `InvalidSignature`, `SelfExchange`, before any key is derived.
- Replayed offer: refused by the completed cache.
- AEAD or CRC failure: `NfcDecryptionFailed`, `NfcCrcMismatch`.
- Tap lost: `NfcSessionLost`, or `RelayFallback` when a key exists.

### Security considerations

- Physical contact is the authentication: the reader talks to the tag
  it touches. The signatures and the identity binding in `info` make
  a *substituted* offer fail at the key rather than later. A *relayed*
  tap does not fail: two honest devices whose APDUs an attacker
  forwards over a distance derive the same `K` with each other, and
  each ends with a contact it did not mean to make, at trust level
  `High` (C5). Nothing in the handshake measures distance or time of
  flight; the level assumes the tap was not relayed.
- Both offers are readable by an NFC sniffer at contact range:
  identity keys, fresh public keys and timestamps. The cards are
  encrypted.
- There is no Tamarin model of the NFC handshake; its properties
  follow the QR model's shape (fresh DH, identity-bound info) and the
  BLE handshake's AAD discipline, and are backed by
  `nfc_handshake_tests.rs` and the inline UKS tests in
  `nfc_handshake.rs`.

### Vectors

None yet. Candidates: an offer and ack pair with the derivation of C3
and an encrypted card with its AAD.

---

## D. Reciprocity confirmation

An exchange is complete on one device when its contact is saved; the
other device may have failed after that. Each side proves to the other
that it saved the contact, over the fastest channel available, and the
contact shows the result.

### States

`Reciprocity` (`contact/reciprocity.rs`): `Pending` at completion;
`Confirmed` with a `ConfirmationChannel` of `Audio`, `Ble`,
`RelayEscrow` or `RelaySync`; `Unreciprocated` when a `Pending` contact
is read more than 7 days after its exchange timestamp
(`Contact::reciprocity`); `Unknown` for contacts from before the
feature. A `Confirmed` contact is never sent another `0x03`
confirmation (D3), but `queue_reciprocity_answer` does not check the
state, so a `Confirmed` contact still answers a valid `0x03` from a
waiting peer with a `0x07`.

### Normative operations

Source: `vauchi-core/src/contact/reciprocity_tokens.rs`,
`api/vauchi/reciprocity_send.rs`, `api/sync/card_update.rs`,
`api/vauchi/receive_routing.rs`, `sync/delta.rs`;
`vauchi-app/src/ui/reciprocity_confirmer.rs`.

**D1. Tokens.** `(our_token, their_token)` are derived as in A5 from a
secret only the two sides hold: the raw DH output for the QR session
(A5), the session key for the BLE handshake (B13), and the contact's
stored shared key for the relay-sync tier below
(`Contact::derive_reciprocity_tokens`). Each tier is consistent with
itself on both sides. For a QR exchange the relay-sync tokens differ
from the escrow tokens (`K` is not `ss`); for the BLE handshake they
are the same value, since the app stores `SK` as the contact's shared
key and both compute `HKDF(SK, "vauchi-reciprocity-confirm-v1" ||
id)`.

**D2. Relay escrow tier** (`ReciprocityConfirmer`, QR and cable
exchanges). Right after completion each side deposits its raw 32-byte
`our_token` in `(gate, own slot)` of A5 with a 7-day TTL and polls the
gate every 30 s; when the gate holds two slots it retrieves the other
slot and compares the blob in constant time with `their_token`. A
match is `Confirmed` over `RelayEscrow`; any other blob is `Pending`
with no retry; an escrow failure is retried three times, up to four
deposits in all (`MAX_DEPOSIT_RETRIES`), and then `Pending`. The screen stays on "Verifying" until the tier
resolves; both outcomes keep the contact, since the peer's keys are
already in hand and only the peer's save of ours is unconfirmed. The
relay sees two 32-byte deposits per gate; the gate is derived from the
same secret as the tokens, so an outsider cannot find it. Relay rules
are those of the escrow in
[Link and Relay-Mediated Exchange](link-exchange.md), A6.

**D3. Relay sync tier** (`queue_reciprocity_confirmations`). On every
sync cycle, after the receive phase, each still-`Pending` exchanged,
unblocked contact with a ratchet and no update already queued gets one
payload inside the ordinary ratchet envelope:

```text
0x03 || token(32) || Ed25519 signature(64)
signature over "vauchi-sync-reciprocity-confirm-v1" || sender_pk || recipient_pk || token
```

On the wire it is a card update like any other. The receiver MUST
verify the signature with the contact's identity key and its own as
recipient (`card_update.rs`, `SignatureInvalid` otherwise), then
compare the token in constant time with the one it expects from that
contact (`resolve_reciprocity_confirm`); only then is the contact
`Confirmed` over `RelaySync`. A sender that was still waiting is
answered with the same payload under version `0x07` and domain
`"vauchi-sync-reciprocity-answer-v1"`, which is never answered in turn
(vauchi/private#663). Mutually confirmed pairs stop sending, so the
exchange converges.

### Failure cases

- Escrow unreachable or refused three times: `Pending`, resolved later
  by D3.
- Blob of the wrong length or value: `Pending`, no retry.
- Bad signature or wrong token on a synced confirmation: rejected, the
  contact stays `Pending`; a reflected message, our own confirmation
  sent back, fails because the tokens are asymmetric.
- 7 days without confirmation: `Unreciprocated`, shown as such.

### Security considerations

- **A confirmation means the peer confirmed.** For the relay-sync tier
  the receiver needs a valid signature by the contact's identity key
  over the recipient and the token, and the token must be the one
  bound to the contact's identity; a reflected message fails on the
  token, a forgery with a leaked shared key fails on the signature.
  This is claim [S7](../claims.md): lemmas
  `confirmed_means_the_peer_confirmed` and
  `a_leaked_shared_key_also_needs_the_identity_key` in
  `reciprocity.spthy`. CI expects the second falsified under
  `-DNO_SIGNATURE`, and the first only under `-DNO_SIGNATURE
  -DSYMMETRIC_TOKENS`: signature and asymmetric tokens each stop a
  reflection.
- **The escrow and link tiers have no signature.** D2 compares a raw
  token and B13 an AEAD under the session key; on those tiers the
  secret they are derived from is the proof, and whoever holds it
  (the two devices, or an attacker who broke the exchange itself) can
  confirm. S7's "identity key is also needed" holds for the relay-sync
  tier; the other two tiers rest on the exchange's own secrecy (S6).
- **What the relay learns.** On D2, a gate with two 32-byte deposits,
  linkable to nothing else; on D3, one more ratchet-encrypted update of
  the usual shape.

### Vectors

The token pair of D1 for the QR tier is in `qr_symmetric`
([Test Vectors](../vectors.md)), with the escrow gate and slots of
D2. A signed `0x03` payload of D3 is a candidate.

---

## E. Multi-stage animated QR: Hover and TapHoverShake

Both phones show a cycling sequence of QR frames, front screen to front
camera, and each reads the other's. The frames carry the whole card, so
the exchange needs no radio and no relay. TapHoverShake adds a shake
check (E10); it is deferred and not offered (see the mode list above),
so the app runs this protocol through Hover.

### Message flow

```text
Alice                                                     Bob
  | 1 INI3(sid_A, eph_A, ch_A, name_A[, relay_A])     INI3 for Bob
  | 2 T = HKDF(X25519(eph_A, eph_B), "vauchi-multistage-v1")
  | 3 DAT4: chunks of C_A = Enc(rk_A, P_A) under T, with an ACK
  |   of Bob's chunks                                 DAT4 for Bob
  | 4 RVL4(sid_A, rk_A)        Alice holds C_B, Bob acked all of C_A
  | 5 open C_B with rk_B; check ch_B and P_B (E3, E6)
  | 6 CNF4(sid_A, rk_A, tag_CNF)        only after every check passed
  | 7 Bob's CNF4 verifies: Finalized; the app saves Bob
  | 8 DON4(sid_A, rk_A, tag_DON)        only after the save succeeded
  | 9 saved and Bob's DON4 read: BTH4(sid_A, rk_A, tag_DON) for 3 s
  | 10 reciprocity confirmation (D3)
```

`P = 0x02 || id || sig || card`: the sender's identity key, its
signature over this session (E3) and its card.

### Normative operations

Source: `vauchi-core/src/exchange/multistage/` (`session.rs`,
`qr_codec.rs`, `payload.rs`, `confirmation.rs`, `commitment.rs`,
`chunker.rs`, `accel_envelope.rs`); orchestration
`vauchi-app/src/orchestrator/multi_stage_machine.rs`,
`ui/app_engine/multi_stage_exchange.rs`; persisting
`vauchi-core/src/api/vauchi/exchange.rs`.

**E1. Frames** (`qr_codec.rs`). A frame is a four-character prefix,
the eight-character training header of the link trainer, which carries
the layout and read counts and no secret, and a base45 body, drawn in
QR alphanumeric mode at error correction L. The prefixes are `INI3`
(opening), `DAT4` (data), `RVL4` (reveal), `CNF4` (confirm), `DON4`
(done), `BTH4` (both), `FAI3` (fail) and `SHK3` (shake envelope). A
frame under a retired prefix (`INI2`, `IN2D`, `DATA`, `VRFY`, `CONF`,
`RDYY`, `FAIL`, `SHAK`, `CMBO`, `DAT3`, `IN3D`, `FIN3`, `DON3`,
`BTH3`) changes
nothing and is reported as coming from an older version: builds on
either side of a prefix change cannot complete this exchange. A phone
ignores a frame that carries its own session id, its reflection in the
other screen.

**E2. Opening and transport key.** Each session draws a 16-byte session
id, a fresh X25519 ephemeral key and a random 32-byte reveal key. The
`INI3` body is the session id, the ephemeral key, the commitment hash,
the display name with a two-digit length, a flags byte and, when its
flag is set, the relay URL with a three-digit length, validated as a
relay URL at parse time in builds with networking. A session accepts an `INI3` only while it
advertises, and then derives

```text
T  = HKDF-SHA256(salt none, X25519(eph_own, eph_peer), "vauchi-multistage-v1")
C  = XChaCha20-Poly1305(rk, P)
ch = SHA-256(rk || C || ctx),  ctx = len32_be(relay) || relay, or empty
```

A non-contributory X25519 result fails the session (`handle_init`).
`C` and `ch` are made in `commitment.rs`.

**E3. Payload** (`payload.rs`).

```text
P   = 0x02 || id(32) || sig(64) || card_json
sig = Ed25519_id("vauchi-multistage-payload-v2" || sid || eph || id
                 || len16_be(relay) || relay || card_json)
```

`sid`, `eph` and `relay` are the sender's own, as its `INI3` shows
them; `card_json` is its contact card. The identity signs inside the
session constructor and its key is not kept (`for_identity`). A
receiver MUST check, in this order: version 2; at least 97 bytes; a
card of at most 65536 bytes (`MAX_CARD_SIZE_BYTES`), before the
signature is checked; the signature, under the identity key the
payload carries, over the peer's session id, ephemeral and relay URL
as its `INI3` showed them; an identity that is not its own, so two
devices of one identity do not exchange; and a card that parses, has
at most 200 fields and whose every field validates. A failure fails
the session, and no confirm leaves the phone. The signature covers the
sender's side only, because a payload is committed before its peer is
known; the confirm (E7) binds it to this session.

**E4. Data.** The commitment ciphertext `C` is cut into chunks, sized
once from the read rate the peer has reported, so that indices and the
ACK bitmap stay valid for the whole transfer. A `DAT4` frame carries
the session id, the chunk index and total, the sender's ACK bitmap of
the peer's chunks, a CRC-16 and the chunk sealed with
ChaCha20-Poly1305 under `T`, a random 12-byte nonce and the associated
data `"vauchi-multistage-data-v4" || sid || index_le16 || total_le16
|| ack`, so an ACK is authenticated with the chunk it travels with. A
`DAT4` from a session other than the bound peer's, or whose total is
zero, whose index is not below its total, or whose total differs from
that of the first chunk that opened, is dropped before the phone keeps
anything of it. A chunk that does not open is dropped and counted, and
the phone sets up its receive buffers only once a chunk has opened.

**E5. Reveal.** `RVL4` is the session id and the reveal key. A phone
shows it once it holds every chunk of the peer and the peer has
acknowledged every chunk of its own, and until its checks of E6 pass.
A reveal read while the phone is still transferring is kept and used
once the last chunk arrives.

**E6. Checks before a confirm.** With the peer's reveal key a phone
checks the peer's commitment hash in constant time, opens `C` and
checks the payload (E3). Only when all of them pass does it confirm:
no confirm tag is computed before (`tag_for` returns none until the
peer's payload is open).

**E7. Confirm and done** (`confirmation.rs`).

```text
K   = HKDF-SHA256(salt none, T, "vauchi-multistage-confirm-v3")
tag = HMAC-SHA256(K, label || sid_s || sid_r || eph_s || eph_r
                  || ch_s || ch_r || SHA-256(P_s) || SHA-256(P_r))
```

`label` is `"CNF"` in a confirm and `"DON"` in a done; `s` is the
sender, `r` the receiver. `CNF4` and `DON4` are the session id, the
reveal key and the tag: 132 characters with the header, QR version 5,
the size of the opening frame. A phone that has passed its checks and
reads its peer's `CNF4`, or a `DON4`, whose tag verifies is
Finalized. A tag that does not verify is ignored, as a misread is, and
the peer's next frame decides; a peer that re-handshakes (E11) shows
frames bound to its old partner until it does. A confirm or done read
before the phone's own checks finished is kept with its label and
checked when they finish. A confirm or done from another session id is
ignored.

**E8. Saving.** On Finalized the app saves the identity and card the
payload verified for (`received_peer`) as an exchanged contact with
`T` as its shared key, seeds the Double Ratchet as in A8, and records
reciprocity Pending, which relay sync resolves (D3). The contact, its
ratchet and a restored contact's new key are written in one storage
transaction, so a failed write leaves none of them behind. Only after the
save succeeded does it tell the session (`mark_saved`), which then
shows `DON4` in place of `CNF4`. A failed save fails the exchange
(`save_failed`): no done is shown, and the phone shows `FAI3` (E9). A repeat exchange keeps the
first exchange's keys (B12). A contact restored from a guardian backup
and waiting for its rekey (Social Recovery C5) takes `T` only once
the peer's verified done tag has been read, in `DON4` or `BTH4`
(`save_exchanged_contact_before_peer_saved`, then
`save_exchanged_contact`); until then it gets the new card, keeps its
old key and goes on waiting.

**E9. Ending.** A `DON4` whose done tag verifies tells a phone its peer
saved. A phone that saved and read its peer's done shows `BTH4`, the
done frame's layout and tag under its own prefix, for 3 seconds; a
saved phone that reads its peer's `BTH4` and verifies its tag stops at
once and knows its peer saved, though it may never have read a `DON4`.
A phone that has not saved neither shows nor obeys `BTH4`, and a
`BTH4` whose tag does not verify is ignored. Without either, a finalized phone keeps showing its frame
for 60 seconds.

A phone whose check of the peer's payload failed (E3), or whose save
failed (E8), shows `FAI3`, its own session id, for 3 seconds
(`FAIL_LINGER`) and then nothing, so its peer stops at once instead of
waiting out its timeout; the app shows the failure when the 3 seconds
are over. A phone acts on a `FAI3` only from the peer it is bound to,
and never once Finalized: the frame carries no tag, and its session id
is on the sender's screen. Failures a restarted peer could explain (a
commitment that does not match, a ciphertext that does not open) show
nothing and leave the re-handshake of E11 possible. `FAI3` carries no
tag: it ends a display or fails an exchange that has not finalized, and
never saves, rekeys or confirms anything.

**E10. TapHoverShake.** The phones also record a shake. `SHK3` carries
the motion envelope sealed under `T` (`accel_envelope.rs`), interleaved
with the confirm. While a phone still records, a confirm it reads waits
in Confirming, so the envelope can still be exchanged, and is applied
when the recording stops.

**E11. Peer restart** (ADR-071). A phone left past its opening by a
peer that restarted re-handshakes with that peer's new opening: it
keeps its own session id, ephemeral key, reveal key and commitment,
forgets the peer's, and binds to the new one. Its payload signature,
over its own values only, stays valid.

### State machine

`ProtocolState` (`types.rs`): `Idle` → `Advertising` (first frame
shown) → `Discovered` (peer `INI3`) → `Transferring` → `Verifying`
(E5) → `Confirming` (E6) → `Finalized` (E7); `Failed` from any state.
`Complete` and `RetryReady` stay in the enum for the bindings and are
not entered. The app's machine adds `Completed` when the ending of E9
is over.

### Failure cases

| Case | Result |
|---|---|
| Payload signature does not verify, or names our own identity | `Failed`, no confirm, `FAI3` shown |
| Card too large, unparsable, too many fields, a field invalid | `Failed`, no confirm, `FAI3` shown |
| Commitment hash or ciphertext does not open | `Failed` |
| Confirm or done tag does not verify | ignored; the next frame decides |
| Frame of another session, `FAI3` included | ignored |
| Frame under a retired prefix | ignored, "older version" shown |
| Save fails | `Failed`, no done, `FAI3` shown |
| Last frame lost | one phone saved, the other did not; the saved contact stays Pending (D) |

### Security considerations

The attacker controls every frame channel: Tamarin
`multistage_exchange.spthy` lets it read, drop, reorder and inject
frames, and film either screen. Proven there: a saved card is the card
the holder of that identity committed (`card_authentic`); a phone
saves only after its peer, in that session, accepted it
(`peer_accepted_before_save`); a done a phone believes is true
(`peer_saved_is_true`); and the three still hold with two bindings of
one opening (E11, `-DREBIND`) and with `IN3D` accepted again
(`-DACCEPT_IN3D`). Each mechanism has a control that falsifies its
lemma: no payload signature (`-DNO_PAYLOAD_SIG`), the unkeyed tag of
earlier builds (`-DLEGACY_TAG`), a confirm before the checks
(`-DCONFIRM_BEFORE_VERIFY`) and one label for both tags
(`-DNO_LABEL`). Card validity, two devices of one identity, the
deferred rekey (E8) and reciprocity are outside the model.

In practice the two phones are held facing each other, 7 to 14 cm
apart. To take part an attacker must put their own screen in front of
the user's camera, which a bystander cannot do unnoticed, and filming
both screens at once is hard. What remains:

- The person in front of you who exchanges under their own key is
  accepted: meeting them is the authentication, as in every in-person
  mode. A failed session has shown your card on screen to that person,
  no more than a successful one would.
- `FAI3` carries no tag. Forging one, under the peer's session id read
  off its screen, fails an exchange that has not finalized; it needs a
  screen in the gap between the two phones.
- A restored contact adopts the new key only on the peer's verified
  done, read in `DON4` or `BTH4`. A phone that leaves the exchange before
  it reads one keeps the contact waiting with its old key.
- A lost last frame can leave one phone with a Pending contact the
  other never saved, until reciprocity retires it (D).
- Chunks are sealed with ChaCha20-Poly1305 and random 12-byte nonces
  under a key used for one session only.

Earlier builds took the identity key from a payload nothing signed and
confirmed with an unkeyed hash, so a person who knew only a contact's
public key could replace the card the user held for that contact
(vauchi/private#1217).

### Vectors

None yet.

---

## Sources

- `vauchi-core/src/exchange/session.rs` (the session state machine,
  the symmetric agreement `vauchi-x3dh-symmetric-v2`, proximity
  commands)
- `vauchi-core/src/exchange/qr.rs`, `qr_url.rs` (QR v3),
  `oob_bootstrap.rs` (Glance QR), `exchange_payload.rs`,
  `exchange_payload_proofs.rs` (the 174-byte payload and its Kani
  harness)
- `vauchi-core/src/exchange/ble_advertisement.rs`, `ble_handshake.rs`,
  `ble_payload.rs`, `ble.rs` (advertisement, handshake v4, card
  payload, UUIDs)
- `vauchi-core/src/exchange/nfc_active.rs`, `nfc_handshake.rs`,
  `nfc_card_payload.rs`
- `vauchi-core/src/exchange/key_order.rs`, `ratchet_bootstrap.rs`,
  `confirmation_escrow.rs`, `reciprocity_tokens.rs`;
  `contact/reciprocity.rs`, `contact/reciprocity_tokens.rs`,
  `contact/trust.rs`, `contact/trust_metrics.rs`
- `vauchi-core/src/api/vauchi/reciprocity_send.rs`,
  `receive_routing.rs`, `api/sync/card_update.rs`, `sync/delta.rs`
- `vauchi-app/src/ui/app_engine/glance.rs`, `ble_handshake.rs`,
  `orchestrator/ble_handshake_machine.rs`,
  `ui/reciprocity_confirmer.rs`; `vauchi-cli/src/commands/exchange.rs`
- `vauchi-core/verification/qr_exchange.spthy`, `reciprocity.spthy`,
  `ble_advertisement.spthy`, `ble_handshake.spthy`
- ADR-053 (OOB bootstrap is the authentication root), ADR-007 (domain
  separation), ADR-034 (trust levels)
