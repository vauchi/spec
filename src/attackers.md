<!-- SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- description: One table per attacker on Vauchi: what each holds, sees and can do, from the relay host to a device thief, and which security claims speak to each of them. -->

# Attackers

One table per attacker: what they hold, what they see, what they can
do, and which claims speak to them. Every row is drawn from the
chapters, which name the source; this page only arranges them so that
a reviewer who starts from a threat finds the claims to swing at.
Where a claim is *partial*, its entry in [Security Claims](claims.md)
says what is missing.

## The application relay operator

Holds the gateway host, its database, its logs, its metrics, and the
OHTTP window keys.

- **Sees**: per blob, a mailbox token, a padded size, times of arrival
  and acknowledgement, the ratchet header in the clear and an
  origin-hint blob when present; per fetch, the set of up to 100
  tokens one client asked for together; per day, which tokens received
  how much; the hash of an owner's key on guardian sets and recovery
  proofs; an identity key on a purge; both public keys and display
  names in a short-code exchange offer; the link exchange's gate and
  slot hashes and two deposits per gate.
- **Can**: withhold, reorder, replay and delay blobs; correlate one
  fetcher's per-day requests by their timing on the immediate path
  (requests carry one day's tokens each since core!2060,
  vauchi/private#890); intersect the token sets of one fetcher's
  cycles within a day, whose real tokens repeat while the padding is
  fresh, to tell the two apart (vauchi/private#946); recompute every
  past token of a channel once it also obtains that channel's shared
  key.
- **Cannot** (claims): read a card or an update (S1); forge, replay or roll back an update (S2, partial); learn a client's address, against a
  single host (S3, partial while one operator runs both hops); learn
  an identity from a mailbox token (S4, partial as above); learn
  exact lengths (S5, partial); substitute a key inside a link
  exchange payload (Link Exchange, security considerations); tell a
  duress cover item from a real update (S14, partial).

## The outer relay operator

Holds the proxy host that terminates the client's TLS.

- **Sees**: the client's address, the times and sizes of its
  encapsulated requests, which delayed tickets it collects, and the
  signed key record it caches.
- **Can**: drop or delay requests; rate-limit by address.
- **Cannot**: open a request or an answer (RFC 9458 encapsulation to
  the gateway's key); substitute a gateway key, since the client
  accepts only the anchor's chain and refuses an older window or a
  second key for a held window (Relay B4).

## Both operators together, or one operator of both

The alpha's situation (ADR-037 addendum 2026-09-08): address and
content meet in one party. The delayed path spreads the timing;
nothing else separates them. S3 is partial for exactly this reason.
Host separation closes the gate for the alpha and beta; the first
release requires a second operator.

## A network observer

Sees TLS to the outer relay and the gateway's traffic on the inside.
Learns what the outer relay learns about timing and size, nothing
about content, and nothing about tokens unless it also sits inside
the gateway's network. Against a recorded ciphertext plus a later key
compromise: S11 holds for contact channels and not for sync between
a person's own devices or the first genesis message.

## A bystander at an in-person exchange

Sees both screens or photographs the QR codes; holds a phone in radio
range; may run a sniffer at NFC range.

- **Sees**: identity keys, fresh public keys, names, a relay URL, a
  random token and challenge (QR); both identity keys in the clear in
  the Bluetooth KeyOffer and KeyAck, so who met; both NFC offers at
  contact range.
- **Can**: put a photographed Glance QR's two-byte prefix on the air;
  race a replay of a Bluetooth KeyOffer whose nonce echo it observed
  (vauchi/private#892); complete a radio-only handshake (Bump, Shake,
  Magic) if it wins the tiebreak, since those modes pin nothing;
  forward NFC APDUs over a distance between two honest devices, who
  then exchange with each other at trust level High.
- **Cannot**: derive the session key from the QR transcript (S6);
  make the scanner connect to a device other than the one it scanned
  (S8); forge the relay-sync confirmation (S7, partial: the Glance and
  escrow tiers rest on the exchange's secrecy).

## Someone who obtains a link, a code or a link QR

- **A link** (`vauchi.app/x#pk=..&n=..&v=2`) without its code: one guess
  at the six digits, which cannot be tested offline, and a wrong one uses the
  link up. Whoever holds both, within the sender's 300-second wait, becomes
  the sender's contact (S9, partial).
- **A short code**: whoever claims it first within its TTL takes the
  offer; the real responder then fails visibly; the complete
  authentication fingerprint reveals a substitution only when both
  people compare every group over an authenticated independent channel.
- **A device-link QR**: the link key. Against an honest relay the
  user's new device shows a different code and the host does not
  release the seed; against a relay the attacker can read, the seed
  is lost (S15, stated as the limit).

## A thief with the device

Holds the device, powered off or locked, its file system and its
secure storage, or a backup file; possibly the old device of a
recovering user.

- **Can**: read the database if the platform secure storage yields
  the raw storage master key; recover the seed and every key from it;
  read the receive state, ratchet states and the mailbox tokens stored
  ahead, from a phone unlocked once since boot, because secure storage
  yields the background receive key then even while the phone is
  locked (S12);
  brute-force a six-digit duress PIN offline from its Argon2id hash;
  guess a backup's password at Argon2id cost, past the strength gate
  both the full backup and the identity-only export apply
  (vauchi/private#891); as the holder
  of a recovering user's old device, hold every old shared key.
- **Cannot**: open the data once the storage master key is destroyed
  (S12, partial on the phones); open a backup without its password
  (S13); use the old device to make a contact accept a false recovery
  when fewer than two of the helpers it counts are corrupt (S16,
  partial); recover from fewer than the threshold of guardians (S17,
  partial).

## A coercer with the owner and the unlocked device

Watches the unlock and the network, may hold the relay.

- **Gets**: a decoy contact list under the duress PIN, a session copy
  of the card, cover traffic of the right length and timing to every
  contact and device (S14, partial: the duress model proves the cover
  indistinguishable on the wire, but leaves lengths, timing and the
  linked devices to the tests).
- **Breaks it by**: extracting the ratchet keys from the device, the
  model's stated limit; or imaging the storage, where the duress
  hash is guessable.

## A contact

Holds a shared key and a ratchet with the user, and the fields the
user granted.

- **Can**: send what it likes over its own channel; name a relay URL
  in its QR, which is stored and not routed by; send a resync request
  once a day; keep what it was sent after a grant is revoked; as a
  helper, vouch for a photographed recovery claim for up to 192 hours.
- **Cannot**: receive a field it was not granted (Keys and Cards G2);
  raise its own trust level (S10); impersonate another contact (the
  delta signature binds sender and recipient, S2); learn the owner's
  other contacts.

## Against the notice core (proposed)

The [Notice Core](protocols/notice-core.md), the key delivery of
mailbox cohorts (ADR-081), is a proposed design and not in the app. It
is designed against two attackers; its claims are under Notice core
(proposed) in [Security Claims](claims.md#notice-core-proposed), and
are reviewed claims, not shipped properties.

### The gateway: both relays colluding, without keys

Holds the outer relay and the application relay together (the
chapter's G), and no device keys. The devices' clocks may be up to
three days apart.

- **Sees**: every write and every read of the cohort; which devices
  registered in it and when each wrote (Relay A11).
- **Can**: drop, delay, reorder and replay records; alter or inject
  bytes; withhold acknowledgements, so that devices send again; deliver
  an older refresh after a newer one, which moves the sender back for up
  to a refresh period with no alarm. Dropping or delaying delays the
  card until the next refresh period brings the view, the content and
  an opening again; replays are dropped.
- **Cannot** (claims): raise an alarm, or stop the receiver converging
  on the latest card once it delivers again, while the clocks stay
  within their bounds (P5); tell a control record from an update notice
  or a dummy, link a direction's records, or learn who writes to whom
  within a cohort (P6, argued for a gateway that watches, delays, drops
  and replays, not for one that adapts its tampering to what it
  observes).

### A copy of a device

Someone who copied the full state of the sender's or the receiver's
device once, at one moment, and does not see state the device creates
later (the chapter's T). Not defended: a copy the gateway helps, or an
attacker who copies state again and again.

- **A copy that only reads** the cohort: reads what the copied keys
  still open. It holds superseded update keys only within the stated
  windows (P2), and loses access to updates made afterwards once the
  receiver has made a refresh after the copy, the sender has opened it,
  the receiver has named the new epoch and the sender has followed that
  name: up to about four refresh periods (P3).
- **A copy that writes** records as well: the notice core promises best
  effort only. It can take the sender's writing epoch; keep the
  receiver's own refreshes from opening by forging one higher-numbered
  refresh a week, so healing never starts while it writes, with no
  alarm; trap the receiver in its epochs; hide a record until the
  weekly view replaces it; spend the sender's resources; and shorten
  what the sender keeps (Security Claims, Not claimed: a copy that
  writes). A copy of the sender also holds the identity key and signs
  cards as the sender, which is outside the notice core.

## Not an attacker here

A platform vendor, the app stores, the operating system and the
hardware are trusted; a compromised platform secure storage yields
the storage master key and so everything. Organisation identities are
out of scope ([Conventions](conventions.md)).
