<!-- SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Changelog

Each spec tag maps to the Core commit it was extracted from.

## Unreleased

- Social Recovery A8 and Update and Sync B5: taking a guardian out of
  the set sends it a bodyless `0x0c` release, and the guardian forgets
  what that sender left (vauchi/private#796).
- Social Recovery A7 and A8: the delivery carries the owner's export
  time ahead of the share, and a guardian keeps each owner's newest
  whole delivery, in the receive transaction, dropping one that does
  not add up and holding at most two unfinished (vauchi/private#796).
- Social Recovery, What ships today: each change to the recovery-trusted
  contacts sends three to nine guardians a fresh guardian backup with
  their shares, at the voucher threshold capped at the guardian count
  (vauchi/private#796, D10); guardians do not keep it yet. The A7 names
  are on Core main since core!2153 and leave `claim-names.pending`.
- Social Recovery A7 and Update and Sync B5: a guardian backup travels
  to its guardian as `0x0b` ratchet messages of at most 48 KiB, each
  naming its backup, count, index and the delivery's SHA-256, with the
  receiver's refusals; nothing sends or keeps one yet
  (vauchi/private#796, core!2153).
- Conventions: Core's formal job is two jobs, `test:formal-code` for the
  Kani harnesses and wipe tests and `test:formal-models` for the Tamarin
  and Quint models, each on the merge requests that touch what it checks
  (core!2151, vauchi/private#1032).
- Conventions and Claims: the end-to-end lane cases carry `@claim: S<n>`
  since e2e!288, the nightly runs four drift checks, and the wire-format
  row names the formats still without a schema (vauchi/private#874).
- Wire Schemas: the relay's `/v2` request and response bodies as a JSON
  Schema generated from `vauchi-protocol`'s types, with the parser's
  bounds written in and one example per type; Core proves each bound
  against the parser and `check:wire-schema` compares the copy here with
  Core's and validates the examples (ADR-076 decision 5,
  vauchi/private#119).
- In-Person Exchange B5: the Glance displayer spends its OOB nonce on
  the first accepted KeyOffer and refuses a replay or a second scanner
  with `OobNonceReplayed` (vauchi/private#892, core `issue/892`); the
  "not enforced yet" sentence is gone.
- In-Person Exchange A6, A7 and the Glance notes: one side emits the
  audio challenge first, a confirmed proximity is not lowered, the
  contact's exchange time is the session clock's, the QR contact is a
  placeholder named after the peer's QR, and a Glance displayer's own
  60-second window closes (vauchi/private#948, core `issue/948`). The
  three #948 defect sentences are gone.
- Social Recovery A4, B1 to B3: at most nine recovery-trusted contacts
  (vauchi/private#929, core `issue/929`); exact-length claim, voucher
  and proof parsers, the proof at version 2 only, a threshold of 1 to 9
  validated, the guardian token under the voucher signature as format 3
  with format 2 refused, a 10-minute future skew on claims and vouchers,
  and the old-key voucher refused while collecting (vauchi/private#930,
  core `issue/930`). The #930 defect bullet is gone. Kani harnesses
  for the voucher and token parsers and the time bounds are named; one
  byte of real Shamir arithmetic did not finish and is not
  (vauchi/private#937).
- Relay A7: the purge body carries no `recipient_id`; the relay erases
  the mailbox addressed by the verified signing key, checks every
  signature with dalek `verify_strict`, and lower-cases the hex ids of
  send, ack and fetch after validating them, before the rate-limit
  token is spent (vauchi/private#944, relay `issue/944`, core
  `issue/944`). The three #944 defect sentences are gone.
- Social Recovery B3: the stored proof is sealed to the old key, a
  33-byte plain header (version 3, `new_pk`) and an encrypted body; the
  relay reads the header only and no longer checks an old key against
  the slot. The threat model's relay row and the plain-proof note
  follow; the `recovery_proof` vector is added (vauchi/private#936,
  core and relay `issue/936`). The daily rotation of the lookup hash is
  vauchi/private#998.
- Card Update and Sync D: fetch padding is deterministic per identity and
  day (vauchi/private#946 part 1, core `issue/946`); the chapter states
  the former defect and what remains, the yesterday-token link between
  consecutive days.
- Social Recovery B3: the relay keeps one proof per owner under a key
  hash (at most four), binds a slot to the proof's `new_pk`, refuses
  unsigned uploads, takes the rate bucket lowercase and keeps proofs
  9 days (vauchi/private#927, relay `issue/927`). The #927 defect
  bullet is gone; the failure case for an aged proof says 9 days.
- Social Recovery B2: the CLI's `recovery vouch` now goes through
  Core's contact check (vauchi/private#928, cli `issue/928`); its
  defect bullet is gone.
- Social Recovery C: the revocation tombstone keeps the key and the
  contact's name, and the vouch check accepts it, so a thief's
  revocation cannot silence the real recovery's helpers
  (vauchi/private#935, core `issue/935`).
- Social Recovery B4: a contact refuses a proof whose earliest voucher is
  older than 192 h, not 90 days; the recovery is one 192-hour window
  (maintainer, 2026-10-30, vauchi/private#959). Core's check landed
  the same day (core `issue/959`, vauchi/private#926).
- Card Update and Sync B: the held-back responder message now decrypts
  (vauchi/private#943, core `issue/943`); the chapter states the cause
  and the count bound on skipped keys instead of the defect.

- Every chapter checked against Core `a9a911b0a`, relay `f3034bb` and
  ohttp-relay `a4e7c6e` (vauchi/private#951). Statements that were
  wrong are corrected. Code defects found are stated as defects
  against their MUST and filed as vauchi/private#941 to #950. They
  include:
  - a BLE contact stored under the identity in the peer's card;
  - a link-exchange signature that covers neither the card nor the
    exchange;
  - a lost held-back ratchet message;
  - relay purge unbound to the mailbox;
  - fresh fetch padding that reveals the real tokens;
  - cross-device rollback;
  - a duress PIN's existence visible at rest.

  Claims S8 and S15 are now partial. S11 names the paths without
  forward secrecy. S13 and S14 are no longer stale. The conventions
  table says what each check really checks.
- Social Recovery: the recovery window is measured on the vouchers: a
  proof's vouchers span at most 96 h, a helper refuses claims older
  than 192 h, a contact refuses a proof whose earliest voucher is over
  90 days old, and showing the same old key again resumes the claim in
  progress (maintainer, 2026-10-30). Core still runs the old rules
  (vauchi/private#919, vauchi/private#926).
- Social Recovery checked against Core `a9a911b0a` and relay `f3034bb`.
  Corrected:
  - three to nine guardians;
  - proofs are stored in the clear;
  - the token signs `created_at`;
  - a sealed shard is 124 bytes, and the sealed box binds neither key
    into its derivation;
  - at most 252 restore subsets;
  - the Kani harnesses stub what they stub;
  - the relay keeps one proof per hash, owned by its first signer, and
    the revocation and conflict detection are not wired;
  - `accept_recovery` overwrites the shared key;
  - guardian tokens prove nothing against the thief.

  New defects: vauchi/private#927, #928, #929 and #930. S16's statement
  names the attacker its lemma keeps the key from.
- Protocol audit corrections: BLE commitments do not provide fair
  exchange; device linking and sync bootstrap fresh pairwise ratchets
  rather than copying live states. Mailbox tokens also authorize
  destructive acknowledgement, and purge signatures do not prove
  mailbox ownership.
- Pending coordinated fixes: card payload identities are bound to the
  authenticated BLE/NFC peer; relay exchange compares the complete
  HMAC fingerprint, with incompatible legacy comparison strings; mailbox
  admission and fetch pages fit their exact serialized delivery limits,
  retaining and reporting oversized legacy rows. Signed per-field clocks
  and persistent removal tombstones prevent sibling-device rollback;
  owner-device sequences preserve replay ordering across retries and
  reloads, with data and ordering writes committed together.

- Related Work: the Signal protocols and sealed sender, Pond, Briar's BQP,
  Magic Wormhole, Delta Chat's SecureJoin, SimpleX, Session, the PGP web
  of trust, Zooko's triangle and petnames, Plaxo, local-first software and
  social-recovery wallets, each with what Vauchi shares, where it differs
  and where it is weaker; the short-code exchange is named as weaker than
  Wormhole's PAKE (vauchi/private#119).
- The drift checks run nightly (spec!12); claim annotations `@claim: S<n>`
  in Core and e2e with `check:claim-annotations` (spec!13); Core's
  `check:spec-names` (core!2078) and the `Spec:` commit trailer (VGT12)
  close the loop from Core's side; S5 names its padding tests.
- The disclosure page names the PGP key for security@vauchi.app and its
  fingerprint (vauchi/private#905); reports no longer have to travel in
  clear.
- Vectors `qr_symmetric` (the mutual QR key, tokens and confirmation
  escrow) and `link_exchange` (one link exchange end to end), from
  Core's vector suite; the in-person and link chapters point at them.
- The Attackers chapter and the conventions table of what holds each
  statement true (spec!5); the claim-name CI check with its pending
  list (spec!6); the image and deploy trigger for vauchi.app/spec
  (spec!7). `contact_only_after_approval` left the pending list when
  core!2066 put the round-8 models on Core `main`.
- Disclosure Policy: the 48-hour reply and 7-day assessment the short
  forms already promised; high and critical findings are fixed
  privately and published with their release; medium and above get a
  CVE (maintainer, 2026-10-29).

## 0.1-draft (2026-10-28)

Extracted from Core `612992b0b`, relay `9b869ac3b` and ohttp-relay
`a4e7c6eed`; the claims audited against the chapters on Core `main`
`56944aa62` the same day. Tag:
<https://gitlab.com/vauchi/spec/-/tags/0.1-draft>.

- Claims audited against the extracted chapters (2026-10-28): S7, S11
  and S17 become *partial* (the identity signature exists on the
  relay-sync confirmation tier only; device sync and the first genesis
  message have no forward secrecy; the recovery rekey is a design);
  S2 and S6 cite the tests that back them instead of a lemma without
  a verdict and tests of another agreement; S4 names the fetcher's
  cross-day linkability (vauchi/private#890) and the identity-keyed
  relay routes; S10's attacker is the one its test covers; S13 says
  the full backup has no password strength check
  (vauchi/private#891). Chapters: a relayed NFC tap is not refused;
  a contact's relay URL is stored, not routed by; the duress PIN's
  hash is brute-forceable offline; the Glance nonce and the two
  Bluetooth paths cite their issues (vauchi/private#892, #893).

- Vectors: `backup_v6` added from Core `main` after core!2054, the
  file the app writes today, with its two Core tests named under S13.
  The sync chapter no longer describes the removed delivery-receipts
  flag (core!2056).

- Chapters "In-Person Exchange", "Keys and Cards", "Card Update and
  Sync", "Relay" and "Social Recovery" extracted 2026-10-28 from Core
  `612992b0b`, relay `9b869ac3b` and ohttp-relay `a4e7c6eed`. Every
  placeholder is now a chapter; each names where the code is weaker
  than a claim's sentence (S7's signature argument holds for the
  relay-sync tier only; S13's shipped backup is v6; S16 stops at the
  verdict; device-to-device sync and the first genesis message have no
  forward secrecy; one operator runs both relay hops).

- Chapter "Link and Relay-Mediated Exchange" extracted from Core
  `68d7626c6` and relay `525334985`: link format, nonce-derived
  handshake slots, escrow derivations, the relay's two-slot rules, the
  signed v2 card payload, completion and ratchet seeding, deadlines and
  failure cases; the short-code offer, claim and complete flow with the
  SAS derivation. Backs S9.

- Conventions, the claims chapter S1 to S17 (extracted 2026-10-28 from
  the docs site's security-claims page, verified against Core `main`),
  the test vectors v1 (Core
  `vauchi-core/tests/fixtures/test-vectors/vauchi-protocol-vectors-v1.json`),
  the disclosure policy draft, and placeholder chapters with their
  sources.
