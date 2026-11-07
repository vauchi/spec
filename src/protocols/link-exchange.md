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
the app on both sides and gives both a full authentication fingerprint
to compare. Its separate six-digit code is only for rendezvous. The link
exchange's own six-digit code is different: it confirms the exchange, and the
relay never sees it.

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
  |  blob=pk_i||msg_i (65 B)        |                               |
  |-------------------------------->|                               |
  |  2 share link (any channel):    https://vauchi.app/x#pk=..&n=..&v=2[&nm=..]
  |  3 send the code another way (never in the link)                |
  |  4 poll COUNT(handshake gate)   |            person types code  |
  |  once per advance               |  5 PUT epk                    |
  |                                 |  gate=H(n||"handshake")       |
  |                                 |  slot=H(n||"epk")             |
  |                                 |  blob=pk_r||msg_r (65 B)      |
  |                                 |<------------------------------|
  |                                 |  6 GET(handshake, epk)        |
  |                                 |  -> pk_i||msg_i               |
  |                                 |------------------------------>|
  |                                 |  7 PUT card                   |
  |                                 |  gate=G  slot=S_r             |
  |                                 |  blob=Enc(K_card, payload_r)  |
  |                                 |<------------------------------|
  |  8 GET(handshake, presence)     |                               |
  |  -> pk_r||msg_r                 |                               |
  |<--------------------------------|  9 poll COUNT(G) per advance  |
  | 10 PUT card gate=G slot=S_i     |                               |
  |  blob=Enc(K_card, payload_i)    |                               |
  |-------------------------------->|                               |
  | 11 poll COUNT(G) per advance    |                               |
  | 12 GET(G, S_i) -> payload_r     | 13 GET(G, S_r) -> payload_i   |
  |<--------------------------------|------------------------------>|
```

`n` is the link's nonce, `pk_i` and `pk_r` the two sides' ephemeral
X25519 public keys, `msg_i` and `msg_r` their SPAKE2 messages (A3), `G`,
`S_i`, `S_r` and `K_card` the escrow values derived below, and
`payload_*` the signed card payloads (A9). With a wrong code the two
sides derive different `G`, `S_*` and `K_card`, so steps 9 to 13 never
meet.

### Normative operations

Source: `vauchi-core/src/exchange/link_mode.rs`,
`exchange/link_pake.rs`, `exchange/escrow.rs`, `exchange/link_initiator.rs`,
`exchange/link_responder.rs`, `api/vauchi/link_exchange.rs`,
`api/vauchi/import.rs`.

**A1. Link creation** (`initiator_generate_named`). The initiator
MUST generate a fresh X25519 key pair (`StaticSecret::random_from_rng`)
and a fresh 32-byte random nonce `n` per link. The link is

```text
https://vauchi.app/x#pk=<base64url(pk_i)>&n=<base64url(n)>&v=2[&nm=<base64url(name)>]
```

with base64url and no padding. The whole payload is in the URL
fragment, which browsers never send to the server, so vauchi.app
learns nothing from a link being opened. `nm` is the sender's display
name, truncated to 64 bytes at a character boundary; it is a claim the
link makes, not a verified name. The form the landing page hands to an
installed app, `vauchi://exchange?pk=..&n=..&v=2`, is parsed the same
way. A client MUST refuse a link whose `v` is not `2` or that has none:
such a link has no code behind it, and accepting one keeps the attack
the code removes. The initiator MUST persist its secret key and `n` for
the whole exchange.

The initiator MUST also draw a six-digit code from the CSPRNG, uniformly
over the whole space, show it on the share and waiting screens, and keep
it out of the link and out of what the share sheet receives
(`LinkCode::generate`). The person passes it on another way than the link.

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

**A3. Presence deposit.** Each side runs symmetric SPAKE2 over
`Ed25519Group` (`LinkPake::start`, crate `spake2` 0.4.0 from the fork in
`vauchi/utils/spake2`, which wipes its secrets) with

```text
password = the six ASCII digits of the code
identity = "vauchi-link-pake-v1" || n || pk_i
```

The message `msg` is 33 bytes. The initiator MUST deposit
`pk_i || msg_i` in
`(handshake_gate, presence_slot)` with the default TTL of 604 800 s
(7 days). It does so on the first `advance` of the exchange, after the
app already shows the link (`app_engine/link_exchange.rs`); either
side's deposit creates the gate, so a responder who is faster still
fills it. The relay only serves a gate that holds two slots (A6), so
without the presence deposit the initiator could never read the
responder's key, and the responder could never read `msg_i`.

**A4. Responder key agreement** (`responder_open`, `LinkOpening`). The
responder MUST ask for the code before anything reaches the relay, and
MUST refuse a code that is not six digits (`LinkCode::parse`, which also
takes `123 456` and `123-456`), so that opening a link and stopping uses
nothing up. It then MUST generate a fresh ephemeral X25519 key pair,
compute `ss = X25519(sk_r, pk_i)`, MUST reject a non-contributory result
(`was_contributory()` false, a small-order `pk_i`), and starts its SPAKE2
run. With `K_pake` the 32-byte SPAKE2 key and `ikm = ss || K_pake`, both
sides derive, with HKDF-SHA256 and no salt:

```text
gate_raw  = HKDF(ikm, "vauchi-escrow-pake-gate-v1")       G   = hex(SHA-256(gate_raw))
init_raw  = HKDF(ikm, "vauchi-escrow-pake-slot-init-v1")  S_i = hex(SHA-256(init_raw))
resp_raw  = HKDF(ikm, "vauchi-escrow-pake-slot-resp-v1")  S_r = hex(SHA-256(resp_raw))
K_card    = HKDF(ikm, "vauchi-escrow-pake-card-key-v1")
```

(`EscrowKeys::derive_with_pake`). The initiator uses `S_i` as its own
slot and `S_r` as the peer's; the responder the reverse. There is no
separate check of the code to forget: every value depends on it. The
exchange binding is `(n, pk_i, pk_r)`; the responder knows it once it has
generated its key, and MUST sign its payload for it (A9).

**A5. Responder deposits.** The responder MUST deposit `pk_r || msg_r` in
`(handshake_gate, epk_slot)` with the 7-day TTL, then retrieve the sender's
deposit with `GET(handshake_gate, epk_slot)`, since it cannot derive the
escrow values before it holds `msg_i`. A deposit of any length but 65
bytes, or naming another key than the link's `pk_i`, MUST end the exchange
(`HandshakeFailed`). So MUST a SPAKE2 message that is invalid. Only then
does it derive the escrow values and deposit its encrypted card
`Enc(K_card, payload_r)` in `(G, S_r)`, also with the 7-day TTL. `Enc` is
XChaCha20-Poly1305 in Core's tagged format (`0x02 || nonce || ciphertext
|| tag`, `crypto/encryption.rs`). When the `epk` deposit is answered
`AlreadyExists` the link was opened before, by someone else or by this
user: the responder MUST end the exchange as `link_already_used` and MUST
NOT deposit its card. Each escrow slot is written once, so the client
reports `AlreadyExists` as a failure (`slot_taken`,
`network/escrow_client.rs`), never as a stored deposit. That write-once
slot is what limits a link to one guess at its code. A client resends a
request the OHTTP relay answered 502, which it also does after the put was
stored (`network/http_transport.rs`); the resent deposit is the same bytes,
so it is the same guess, and the relay answers it `Stored` (A6).

**A6. Relay escrow rules** (`relay/src/escrow.rs`,
`vauchi-protocol/src/escrow.rs`). A gate holds exactly two slots. A
PUT MUST be refused when the blob exceeds 65 536 bytes decoded
(`BlobTooLarge`), when `ttl_seconds` exceeds 604 800 (also reported
as `BlobTooLarge`), when the slot already exists in a live gate with
another blob (`AlreadyExists`; the same blob again MUST be answered
`Stored` and change nothing), when the gate already has two slots, or when a new
gate would exceed 10 000 gates; both are reported as `GateFull`, and
the cap counts expired gates the sweep has not yet removed. A GET MUST
answer `NotFound` for an expired or unknown gate, `NotReady{count}`
while the gate has fewer than two slots (before the requester's slot
is checked), `NotFound` for a requester whose own slot is not in the
full gate, and otherwise the blob of the *other* slot. The slot hash
is the only authentication: knowing a gate hash alone retrieves no
blob. Expired gates are swept every 60 s.

**A7. Initiator key agreement** (`LinkInitiatorSession`). When the
handshake gate reports two slots, the initiator retrieves the responder's
deposit from its presence slot. It takes one deposit per session, and MUST
check it is 65 bytes, compute `ss = X25519(sk_i, pk_r)`, reject a
non-contributory result, finish its SPAKE2 run on `msg_r`, refusing an
invalid message and its own message reflected back
(`LinkPakeError::ReflectedMessage`, since symmetric SPAKE2 would otherwise
complete against itself), derive the escrow values as in A4 with the
initiator role, and only then sign its own card payload for
`(n, pk_i, pk_r)`: the binding contains `pk_r`, so the payload cannot be
signed when the link is created. It encrypts the payload with `K_card` and
deposits it in `(G, S_i)`.

**A8. Retrieval.** Each side polls `COUNT(G)` and, when the gate holds
two slots, issues `GET(G, own slot)` and decrypts the returned blob
with `K_card`. A failed decryption is a terminal failure
(`DecryptError`), never a retry with another key.

**A9. Card payload** (`serialize_link_card_payload`,
`parse_link_card_payload`). Each side's payload is one byte `0x03`,
the 64-byte signature, and a JSON body:

```text
0x03 || signature[64] || { "identity_pubkey": [32 B], "x3dh_pubkey": [32 B],
                           "relay_url": "...", "card": <ContactCard> }
```

`x3dh_pubkey` MUST be a fresh X25519 key generated for this exchange
(`X3DHKeyPair::generate()` in `start_link_exchange` and
`accept_link_exchange_payload`). `signature` is Ed25519 by the
identity key over

```text
"vauchi-link-bootstrap-v3" || n || pk_i || pk_r || body
```

where `body` is the exact JSON bytes that follow the signature. The
three fixed-length fields precede the only variable one, so no length
prefix is needed, and signing the bytes as sent needs no canonical
re-serialisation. A parser MUST verify the signature against the
embedded `identity_pubkey` and its own side's binding, and MUST reject
any other version byte (v1 and v2 are retired), an empty payload, and
a payload shorter than its signature.

**A10. Completion** (`complete_link_exchange`). The receiving side
MUST verify the payload for the binding of the exchange it took part
in (A9), and MUST reject a payload whose identity key is its own
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

Initiator (`LinkInitiatorState`): `Polling` → (the responder's deposit,
keys and binding derived) → `AwaitingCard` → (card signed for the binding,
`deposit_card`) → `Retrieving` → (`RelayEscrowBlobReceived`, decrypted) →
`Finalized{card_bytes}`. Any state → `Failed(reason)` with `PollingTimedOut`,
`HandshakeFailed` (bad length, non-contributory key, or an invalid or
reflected SPAKE2 message), `DecryptError`, `DepositRejected` (any
`RelayEscrowFailed`, whatever its gate) or `Cancelled`. Terminal states
ignore every further event.

Responder (`LinkResponderState`), which exists only once the code is typed:
`AwaitingPresence` → (the sender's deposit, keys derived) → `AwaitingCard` →
(card signed for the binding, `deposit_card`) → `Polling` →
(`RelayEscrowReady` on `G`) → `Retrieving` → `Finalized{card_bytes}`; failures
`PollingTimedOut`, `HandshakeFailed`, `DecryptError`, `DepositRejected`,
`LinkAlreadyUsed`, `Cancelled`. `LinkAlreadyUsed` means the `epk` deposit found
its slot taken (A5). `DepositRejected` means the relay refused any other
request on the handshake gate or on `G`: a card over the blob limit, or the
relay at capacity.

Both sessions ignore ready and blob events for gates they do not own;
only the responder also filters `RelayEscrowFailed` to its two gates. Both
persist nothing of the escrow beyond the session: the only durable
result is the contact created in A10.

### Failure cases

- Malformed link (missing `pk` or `n`, wrong length, bad base64, or a
  `v` other than `2`): rejected at parse time; the `nm` name is dropped
  silently when it
  does not decode or carries control, invisible or direction-changing
  characters, never the link.
- Small-order peer key: `NonContributoryDh`, terminal.
- A code that is not six digits: refused on the code screen, with nothing
  sent. It uses up nothing.
- Wrong code: not detectable as such by either side, since a distinguishing
  answer would be a test of the guess. Each side waits in its own gate and
  ends `PollingTimedOut` at its deadline, and the copy says the code may have
  been wrong. A retry needs a new link: the `epk` slot is already written.
- Relay answers `BlobTooLarge`, `GateFull` (including capacity) and
  `NotFound`, and a blob that is not valid base64: `DepositRejected`,
  terminal (on the responder only for its two gates). `AlreadyExists`
  on the responder's `epk` deposit: `LinkAlreadyUsed`, terminal.
- Unknown or expired gate: the relay answers `NotFound`, which ends
  the session `DepositRejected`. With a 7-day TTL against a 300 s
  session this happens only when the relay loses its in-memory store.
- Signature failure, a payload signed for another exchange, or a
  wrong version: completion fails; no contact is created.
- Self-exchange: refused before any write.

### Security considerations

- **Who becomes a contact.** Only someone holding both the link and the
  code, or who guesses the code. Whoever holds only the link gets one
  guess per link, one in a million, and cannot test guesses offline: the
  SPAKE2 messages offer no test, and a wrong guess only leaves the two
  sides in different gates. `link_exchange.spthy` states this as
  `contact_only_after_approval`, *verified* on this design with the winning
  guess excepted as `GuessWon`, and *falsified* on each variant CI keeps to
  show the lemma can fail: `-DFIRST_OPENER` (no code), `-DPIN_CONFIRMED` (a
  hash of a code in the deposit, testable offline) and `-DCODE_IN_LINK`.
  The model assumes SPAKE2's messages offer no offline test; it does not
  prove it. This is claim [S9](../claims.md). `spake2` has never been
  independently audited, and if it were broken the exchange would fall
  back to whoever opens the link first, with the card still sealed from
  the relay, since `ss` stays in the key input.
- **What the code does not do.** It proves possession of the code, not who
  a person is, so the contact stays `Remote` until a fingerprint comparison
  (Keys and Cards G3). If the link and code travel together, or over one
  channel the attacker reads, it protects nothing; the copy can only ask.
  Whoever holds the link can still fill the `epk` slot first: the intended
  person then sees `link_already_used` and has to ask for a new link. That
  is denial of service, not a stranger becoming a contact.
- **What a malicious relay can do.** It sees `msg_i` and `msg_r` and can
  substitute either, but each side finishes one SPAKE2 run per session, so
  it gets one guess against each side per link.
- **What the relay sees.** Gate and slot hashes, blob sizes, timing,
  two deposits per gate, both ephemeral public keys `pk_i` and `pk_r`
  and both SPAKE2 messages (the handshake blobs). The hashes do not link
  the handshake gate to the escrow gate, since one depends on the nonce
  and the other on the shared secret and the code, but timing does: the
  responder's `epk` deposit, GET of the sender's deposit and card deposit
  come in one advance, and so do the initiator's GET of `pk_r || msg_r`,
  PUT of its card and COUNT of `G`. The relay never sees a private key,
  the shared secret, the code or a card.
- **What the card payload binds.** The identity signature covers the
  whole body (identity key, card, X3DH key, relay URL) and the
  exchange `(n, pk_i, pk_r)`. A rewritten card fails verification, and
  so does a payload replayed from another link or relayed by someone
  who swapped `pk` in a shared link: each side then holds a different
  binding, so neither accepts the card the other signed (fixed in
  vauchi/private#942; v2 signed only `x3dh_pubkey || relay_url`). The
  relay cannot open a payload, so it cannot substitute anything inside
  one; and the shared key depends on both fresh X3DH keys, so a later
  compromise of either identity key does not reveal it. The binding
  does not say who opened the link: that is what the code is for, since
  a swapper without it derives another gate.
- **What is not bound.** The escrow shared secret `ss` authenticates
  nobody: it comes from two ephemeral keys. The code confirms that both
  sides hold what the sender gave out, and the signed payload says whose
  card it is, which is why a payload with a bad signature is a terminal
  failure.
- **Sender name.** `nm` is unauthenticated. The filter rejects only C0
  and C1 controls, bidi controls and a few invisible characters
  (U+00AD, U+061C, U+200B–U+200F, U+2060–U+2069, U+FEFF); confusables,
  U+2028, U+2029, U+3164, U+115F and U+180E pass. A shell MUST present
  the name as a claim.

### Vectors

`link_exchange` in [Test Vectors](../vectors.md) is one exchange end
to end: the link of A1 from a fixed nonce and ephemeral key, the
three slots of A2, the escrow gate, slots and card key of A4 under
both roles from a fixed `K_pake`, the signed payload of A9 byte for
byte, and the shared key of A10 from both sides. SPAKE2 itself is not
vectored: its scalar comes from the CSPRNG, so tests run the two real sides
against each other instead.

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
  | 5 both show the full authentication fingerprint; compare  |
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

**B4. Authentication fingerprint** (`derive_sas`). Both sides compute

```text
tag = HMAC-SHA256(key = shared,
                  "vauchi-relay-exchange-sas-v1" || min(id_i, id_r) || max(id_i, id_r))
fingerprint = all 32 tag bytes, lowercase hex, eight groups of eight
              hex characters separated by hyphens
```

with the two identity keys in byte order, so both sides get the same
string. The complete fingerprint is shown to both people; the protocol
does not wait for a confirmation. Old six-digit comparison strings
are incompatible and MUST NOT be accepted as a matching fingerprint.
The HMAC domain and key agreement are unchanged.

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

- The full fingerprint binds the shared secret and both identity keys.
  The people must compare every group over an authenticated independent
  channel; a skipped or partial comparison does not establish the
  intended peer. The former six-digit truncation allowed adaptive
  searches for collisions across two substituted transcripts; it was
  not a PAKE or a commit-before-reveal protocol. Keeping the complete
  HMAC removes that short-output search. This does not add explicit
  approval before contacts are persisted.
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
