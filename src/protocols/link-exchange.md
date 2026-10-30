<!-- SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Link and Relay-Mediated Exchange

> **Status: extracted 2026-10-28** from `vauchi/core` `68d7626c6` and
> `vauchi/relay` `525334985`; checked against `vauchi/core`
> `a9a911b0a` and `vauchi/relay` `f3034bb` on 2026-10-30. Two protocols share this chapter because
> they share the goal and the relay: the **link exchange** (section A)
> and the **relay-mediated exchange with a short code** (section B).
> Claims backed: [S9](../claims.md).

## Goal

Two people who are not in the same place exchange contact cards and
end up with a shared key for updates, using the relay only as a store
that cannot read what passes through it. The link exchange works for a
recipient who does not have the app yet; the short-code exchange needs
the app on both sides and gives both a six-digit comparison code.

## Actors

- **Initiator (sender)**: the person who creates the link or the offer.
- **Responder (recipient)**: the person who opens the link or enters
  the code.
- **Relay**: `vauchi/relay`, holding escrow blobs and short-code
  offers. It stores and forwards bytes; it is not trusted with content.
- **Attacker**: owns the network, the relay, and the channel the link
  or code travelled over (a chat, an email, a shoulder). This is the
  attacker of the Tamarin model `link_exchange.spthy`.

---

## A. Link exchange

### Message flow

```text
Initiator                        Relay                         Responder
  |  1 PUT presence                 |                               |
  |  gate=H(n||"handshake")         |                               |
  |  slot=H(n||"initiator_presence")|                               |
  |  blob=pk_i (32 B)               |                               |
  |-------------------------------->|                               |
  |  2 share link (any channel):    https://vauchi.app/x#pk=..&n=..[&nm=..]
  |  3 poll COUNT(handshake gate)   |  4 PUT epk                    |
  |  once per advance               |  gate=H(n||"handshake")       |
  |                                 |  slot=H(n||"epk")  blob=pk_r  |
  |                                 |<------------------------------|
  |                                 |  5 PUT card                   |
  |                                 |  gate=G  slot=S_r             |
  |                                 |  blob=Enc(K_card, payload_r)  |
  |                                 |<------------------------------|
  |  6 GET(handshake, presence)     |                               |
  |  -> pk_r                        |                               |
  |<--------------------------------|  7 poll COUNT(G) per advance  |
  |  8 PUT card gate=G slot=S_i     |                               |
  |  blob=Enc(K_card, payload_i)    |                               |
  |-------------------------------->|                               |
  |  9 poll COUNT(G) per advance    |                               |
  | 10 GET(G, S_i) -> payload_r     | 11 GET(G, S_r) -> payload_i   |
  |<--------------------------------|------------------------------>|
```

`n` is the link's nonce, `pk_i` and `pk_r` the two sides' ephemeral
X25519 public keys, `G`, `S_i`, `S_r` and `K_card` the escrow values
derived below, and `payload_*` the signed v2 card payloads.

### Normative operations

Source: `vauchi-core/src/exchange/link_mode.rs`,
`exchange/escrow.rs`, `exchange/link_initiator.rs`,
`exchange/link_responder.rs`, `api/vauchi/link_exchange.rs`,
`api/vauchi/import.rs`.

**A1. Link creation** (`initiator_generate_named`). The initiator
MUST generate a fresh X25519 key pair (`StaticSecret::random_from_rng`)
and a fresh 32-byte random nonce `n` per link. The link is

```text
https://vauchi.app/x#pk=<base64url(pk_i)>&n=<base64url(n)>[&nm=<base64url(name)>]
```

with base64url and no padding. The whole payload is in the URL
fragment, which browsers never send to the server, so vauchi.app
learns nothing from a link being opened. `nm` is the sender's display
name, truncated to 64 bytes at a character boundary; it is a claim the
link makes, not a verified name. The legacy form
`vauchi://exchange?pk=..&n=..` is still parsed. The initiator MUST
persist its secret key and `n` for the whole exchange.

**A2. Slots from the nonce.** All three handshake positions are
SHA-256 over the nonce and a label, hex-encoded:

```text
handshake_gate = SHA-256(n || "handshake")
presence_slot  = SHA-256(n || "initiator_presence")
epk_slot       = SHA-256(n || "epk")
```

They depend on the nonce only, so their hashes do not link the
handshake gate to the escrow gate below, which depends on the shared
secret. Timing does link them (see Security considerations).

**A3. Presence deposit.** The initiator MUST deposit `pk_i` in
`(handshake_gate, presence_slot)` with the default TTL of 604 800 s
(7 days). It does so on the first `advance` of the exchange, after the
app already shows the link (`app_engine/link_exchange.rs`); either
side's deposit creates the gate, so a responder who is faster still
fills it. The relay only serves a gate that holds two slots (A6), so
without the presence deposit the initiator could never read the
responder's key.

**A4. Responder key agreement** (`responder_respond_with_card_bytes`).
The responder MUST generate a fresh ephemeral X25519 key pair, compute
`ss = X25519(sk_r, pk_i)`, and MUST reject a non-contributory result
(`was_contributory()` false, a small-order `pk_i`). From `ss` both
sides derive, with HKDF-SHA256 and no salt:

```text
gate_raw  = HKDF(ss, "vauchi-escrow-gate-v1")       G   = hex(SHA-256(gate_raw))
init_raw  = HKDF(ss, "vauchi-escrow-slot-init-v1")  S_i = hex(SHA-256(init_raw))
resp_raw  = HKDF(ss, "vauchi-escrow-slot-resp-v1")  S_r = hex(SHA-256(resp_raw))
K_card    = HKDF(ss, "vauchi-escrow-card-key-v1")
```

(`EscrowKeys::derive`). The initiator uses `S_i` as its own slot and
`S_r` as the peer's; the responder the reverse.

**A5. Responder deposits.** The responder MUST deposit, in this order,
`pk_r` in `(handshake_gate, epk_slot)` and its encrypted card
`Enc(K_card, payload_r)` in `(G, S_r)`, both with the 7-day TTL.
`Enc` is XChaCha20-Poly1305 in Core's tagged format (`0x02 || nonce
|| ciphertext || tag`, `crypto/encryption.rs`). Both deposits are
dispatched together, so by the time the initiator sees the handshake
gate full the card is normally already waiting (A8).

**A6. Relay escrow rules** (`relay/src/escrow.rs`,
`vauchi-protocol/src/escrow.rs`). A gate holds exactly two slots. A
PUT MUST be refused when the blob exceeds 65 536 bytes decoded
(`BlobTooLarge`), when `ttl_seconds` exceeds 604 800 (also reported
as `BlobTooLarge`), when the slot already exists in a live gate
(`AlreadyExists`), when the gate already has two slots, or when a new
gate would exceed 10 000 gates; both are reported as `GateFull`, and
the cap counts expired gates the sweep has not yet removed. A GET MUST
answer `NotFound` for an expired or unknown gate, `NotReady{count}`
while the gate has fewer than two slots (before the requester's slot
is checked), `NotFound` for a requester whose own slot is not in the
full gate, and otherwise the blob of the *other* slot. The slot hash
is the only authentication: knowing a gate hash alone retrieves no
blob. Expired gates are swept every 60 s.

**A7. Initiator key agreement** (`LinkInitiatorSession`). When the
handshake gate reports two slots, the initiator retrieves the
responder's key from its presence slot and Core turns the blob into
`Event::LinkOpened { peer_public_key }`
(`api/vauchi/link_exchange.rs`). The initiator MUST check the key is
32 bytes, compute `ss = X25519(sk_i, pk_r)`, reject a non-contributory
result, derive the escrow values as in A4 with the initiator role,
encrypt its own card payload with `K_card` and deposit it in
`(G, S_i)`.

**A8. Retrieval.** Each side polls `COUNT(G)` and, when the gate holds
two slots, issues `GET(G, own slot)` and decrypts the returned blob
with `K_card`. A failed decryption is a terminal failure
(`DecryptError`), never a retry with another key.

**A9. Card payload v2** (`serialize_card_payload_v2`,
`parse_card_payload_versioned`). Each side's payload is one byte
`0x02` followed by JSON:

```text
{ "identity_pubkey": [32 B], "x3dh_pubkey": [32 B],
  "relay_url": "...", "signature": [64 B], "card": <ContactCard> }
```

`x3dh_pubkey` MUST be a fresh X25519 key generated for this exchange
(`X3DHKeyPair::generate()` in `start_link_exchange` and
`accept_link_exchange_payload`). `signature` is Ed25519 by the
identity key over `"vauchi-link-bootstrap-v2" || x3dh_pubkey ||
relay_url`; the fixed-length key precedes the variable URL, so no
length prefix is needed. A parser MUST verify the signature against
the embedded `identity_pubkey` and MUST reject any other version byte,
an empty payload, or a signature that is not 64 bytes.

**A10. Completion** (`complete_link_exchange`). The receiving side
MUST reject a payload whose identity key is its own
(`SelfExchange`). If a contact with that identity already exists the
exchange is idempotent: the existing contact and its ratchet are kept.
Otherwise the contact limit is enforced, and the shared key is

```text
shared_key = HKDF(X25519(sk_x3dh_ours, x3dh_pubkey_theirs),
                  "vauchi-link-shared-key-v1")
```

(`derive_link_shared_key`), the same on both sides. The contact is
created with the peer's relay URL, and a Double Ratchet is seeded
through `bootstrap_exchange_ratchet` with the two fresh X3DH keys: the
side with the smaller identity key is the ratchet initiator.

**A11. Deadlines.** Each side's session fails with `PollingTimedOut`
300 s after it was created (`LINK_EXCHANGE_DEADLINE_SECS`); the app
drops the sender's session earlier when the sender leaves the link
screen. The deposits stay on the relay for up to 7 days, but a link
opened after the sender's session ended cannot complete; the sender
has to start a new exchange. The machines attach
`suggested_interval_ms` hints to their checks (30 s on the handshake
gate and the responder's escrow gate, 1 s on the initiator's escrow
gate once its card is deposited), but Core does not use them: it
polls the watched gate once per `advance`, as often as the caller
advances.

### State machine

Initiator (`LinkInitiatorState`): `Polling` → (`LinkOpened`, keys
derived, card deposited) → `Retrieving` → (`RelayEscrowBlobReceived`,
decrypted) → `Finalized{card_bytes}`. Any state → `Failed(reason)`
with `PollingTimedOut`, `HandshakeFailed` (bad length or
non-contributory key), `DecryptError`, `DepositRejected` (any
`RelayEscrowFailed`, whatever its gate) or `Cancelled`. Terminal
states ignore every further event.

Responder (`LinkResponderState`): `Polling` → (`RelayEscrowReady` on
`G`) → `Retrieving` → `Finalized{card_bytes}`; failures
`PollingTimedOut`, `DecryptError`, `DepositRejected`, `Cancelled`.
`DepositRejected` on the responder means the relay refused a request
on gate `G`: a card over the blob limit, or the relay at capacity. A
re-open of a link, or an open after someone else, is not reported:
the `epk` deposit returns `AlreadyExists`, which the client counts as
stored (`network/escrow_client.rs`), and the session ends
`PollingTimedOut` on an escrow gate the initiator never joins (defect
vauchi/private#942).

Both sessions ignore ready and blob events for gates they do not own;
only the responder also filters `RelayEscrowFailed` to its gate. Both
persist nothing of the escrow beyond the session: the only durable
result is the contact created in A10.

### Failure cases

- Malformed link (missing `pk` or `n`, wrong length, bad base64):
  rejected at parse time; the `nm` name is dropped silently when it
  does not decode or carries control, invisible or direction-changing
  characters, never the link.
- Small-order peer key: `NonContributoryDh`, terminal.
- Relay answers `BlobTooLarge`, `GateFull` (including capacity) and
  `NotFound`, and a blob that is not valid base64: `DepositRejected`,
  terminal (on the responder only for gate `G`). `AlreadyExists`
  counts as a successful deposit.
- Unknown or expired gate: the relay answers `NotFound`, which ends
  the session `DepositRejected`. With a 7-day TTL against a 300 s
  session this happens only when the relay loses its in-memory store.
- Signature failure or wrong version on the payload: completion
  fails; no contact is created.
- Self-exchange: refused before any write.

### Security considerations

- **Who becomes a contact.** Nothing in the flow asks the sender who
  opened the link. Whoever obtains the link first, within the 7-day
  TTL and while the sender is still polling, becomes the sender's
  contact with a live shared key. `link_exchange.spthy` states this as
  `contact_only_after_approval` and it is *falsified* on the shipped
  design; with the owner's PIN design (`-DPIN_CONFIRMED`) the lemma
  holds only when the proof binds the opener's identity as well as
  its key. Sender approval and an out-of-band code are open work
  (vauchi/private#727). This is claim [S9](../claims.md): a remote
  exchange over a link is weaker. Core marks a link contact with
  transport `Link` and proximity `Unknown`, but no UI copy warns that
  the first opener wins, and `faq.add_contact.answer` says Vauchi
  never exchanges contacts remotely.
- **What the relay sees.** Gate and slot hashes, blob sizes, timing,
  two deposits per gate, and both ephemeral public keys `pk_i` and
  `pk_r` (the handshake blobs). The hashes do not link the handshake
  gate to the escrow gate, since one depends on the nonce and the
  other on the shared secret, but timing does: the responder's `epk`
  and card deposits go back to back, and the initiator's GET of
  `pk_r`, PUT of its card and COUNT of `G` happen in one advance. The
  relay never sees a private key, the shared secret or a card.
- **What the card payload binds.** The identity signature covers
  `"vauchi-link-bootstrap-v2" || x3dh_pubkey || relay_url` only: not
  the card and not this exchange. A payload whose card is rewritten
  still verifies (defect vauchi/private#942). The relay cannot open a
  payload, so it cannot substitute the X3DH key or the routing address
  inside one; and the shared key depends on both fresh X3DH keys, so a
  later compromise of either identity key does not reveal it.
- **What is not bound.** The escrow shared secret `ss` authenticates
  nobody: it comes from two ephemeral keys and only gates the escrow.
  Authentication rests entirely on the signed payload, which is why a
  payload with a bad signature is a terminal failure.
- **Sender name.** `nm` is unauthenticated. The filter rejects only C0
  and C1 controls, bidi controls and a few invisible characters
  (U+00AD, U+061C, U+200B–U+200F, U+2060–U+2069, U+FEFF); confusables,
  U+2028, U+2029, U+3164, U+115F and U+180E pass. A shell MUST present
  the name as a claim.

### Vectors

`link_exchange` in [Test Vectors](../vectors.md) is one exchange end
to end: the link of A1 from a fixed nonce and ephemeral key, the
three slots of A2, the escrow gate, slots and card key of A4 under
both roles, the signed v2 payload of A9 byte for byte, and the shared
key of A10 from both sides.

---

## B. Relay-mediated exchange with a short code

### Message flow

```text
Initiator                    Relay                        Responder
  | 1 OHTTP exchange_offer       |                             |
  |   {identity_key, exchange_key, display_name}               |
  |----------------------------->|                             |
  | <- code (6 digits)           |                             |
  | 2 tell the code (voice, in person)                         |
  |                              | 3 OHTTP exchange_claim      |
  |                              |   code + {identity_key,     |
  |                              |    exchange_key, ephemeral, |
  |                              |    display_name}            |
  |                              |<----------------------------|
  |                              | -> initiator's offer        |
  | 4 OHTTP exchange_complete    |                             |
  |   code -> responder's payload|                             |
  |<-----------------------------|                             |
  | 5 both show SAS "ddd-ddd"; the two people compare it aloud |
```

Every arrow is an action posted to `/v2/ohttp` (B5).

### Normative operations

Source: `vauchi-core/src/api/vauchi/exchange_relay.rs`,
`exchange/relay_exchange.rs`, `exchange/x3dh.rs`,
`relay/src/exchange_broker.rs`, `relay/src/http_api.rs`. No shell
calls this flow today: `start_relay_exchange`, `claim_relay_exchange`
and `complete_relay_exchange` have callers only in Core's tests.

**B1. Offer** (`start_relay_exchange`). The initiator MUST generate a
fresh X25519 key pair and post, as base64 JSON, its identity key, that
exchange key and its display name. The payload is not encrypted: it
holds the same public data a QR exchange shows. The relay MUST issue a
6-digit code drawn from a space of 1 000 000, MUST refuse a payload
over 65 536 bytes, MUST bound a requested TTL to 30–3600 s, and MUST
refuse new offers at its configured capacity. The defaults, a TTL of
300 s (`RELAY_EXCHANGE_DEFAULT_TTL_SECS`) and a capacity of 10 000
(`RELAY_EXCHANGE_MAX_OFFERS`), are not range-checked, except that a
capacity over 500 000, half the code space, stops the relay at start
(`ExchangeBroker::new`).

**B2. Claim** (`claim_relay_exchange`). The responder posts the code
with its identity key, its long-term exchange key, a fresh ephemeral
X25519 key and its display name, and receives the offer in the same
round trip. The relay MUST refuse a code that is not exactly six
digits, an unknown or expired code, or a code already claimed: an
offer is single-use. The responder then computes, as the
agreement's initiator:

```text
DH1 = X25519(sk_exchange_r, pk_exchange_i)
DH2 = X25519(sk_ephemeral_r, pk_exchange_i)
shared = HKDF(salt = none, ikm = DH1 || DH2, "vauchi-x3dh-key-v2")
```

rejecting a non-contributory output of either. It MUST refuse the
exchange when a contact with the offer's identity already exists, then
creates the contact and seeds the Double Ratchet as initiator with the
offer's exchange key. The relay marks the offer claimed and stores the
response before the client runs any of these checks, so a responder
that then refuses (existing contact, non-contributory key, malformed
offer) leaves the initiator to complete one-sided: its `complete`
returns the stored response and it creates the contact.

**B3. Complete** (`complete_relay_exchange`). The initiator polls
`complete` with the code; `None` until the claim lands. It computes
the same `shared` through `X3DH::respond` with its fresh exchange key
and the responder's exchange and ephemeral keys, refuses an existing
contact, creates the contact, seeds the ratchet as responder with its
fresh key, and MUST zeroize the offer's private key afterwards: the
offer is single-use on the client too.

**B4. Short authentication string** (`derive_sas`). Both sides compute

```text
tag = HMAC-SHA256(key = shared,
                  "vauchi-relay-exchange-sas-v1" || min(id_i, id_r) || max(id_i, id_r))
SAS = (u32_be(tag[0..4]) mod 1_000_000) rendered as "ddd-ddd"
```

with the two identity keys in byte order, so both sides get the same
string. The SAS is shown to both people; the protocol does not wait
for a confirmation.

**B5. Transport.** Every call is an action (`exchange_offer`,
`exchange_claim`, `exchange_complete`) posted through Oblivious HTTP
to `/v2/ohttp`: the payloads are public, but two addresses
coordinating on one code would tell the relay who met whom (ADR-037).
When OHTTP is not configured and direct connections are allowed, the
client falls back to posting `/v2/<action>`, such as
`/v2/exchange_offer`, but the relay's direct routes are
`/v2/exchange/offer`, `/v2/exchange/claim` and `/v2/exchange/complete`
(`http_api.rs`), so the fallback matches no route.

### State machine

Relay offer: `open` → `claimed` (response stored) → consumed by
`complete`; expired offers answer `CodeExpired`. Client: the
initiator holds the offer until `complete` returns; the responder is
done at claim time.

### Failure cases

- Wrong, expired or already-claimed code: refused by the relay with
  a typed error; rate limits apply per code and globally.
- Non-contributory key, existing contact, malformed base64 or a key
  field that is not 32 bytes: refused on the client before any write.

### Security considerations

- The SAS binds the shared secret and both identity keys, so a
  man-in-the-middle who substitutes a key without choosing it produces
  two different strings. But the SAS is about 20 bits and neither side
  commits to its keys before seeing the other's, so an active relay
  can grind its substituted keys (about 10^6 X25519 operations) until
  both strings match; and the payloads carry no proof of possession of
  the claimed identity key. The SAS detects only a non-adaptive
  substitution. This is the known result for uncommitted short
  strings; it has not been run against Vauchi. The people have to
  compare the strings; a skipped comparison is the same trust as a
  link exchange.
- The six-digit code is a rendezvous, not a secret: anyone who learns
  it within the TTL and before the responder can claim the offer. The
  real responder then fails with `AlreadyClaimed` while the offer
  waits for `complete`, and with "invalid or expired code", the error
  for a mistyped code, once the initiator has completed.
- The relay sees both payloads in the clear (public keys and display
  names) and the code; it does not see the shared secret.

### Vectors

`derive_sas` and the two-DH agreement of B2 are candidates for the
vectors file; the `x3dh` entry there already covers the agreement as
`X3DH::respond` computes it.
