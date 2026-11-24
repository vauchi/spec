<!-- SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- description: Changes to the Vauchi protocol specification, each spec tag mapped to the Core commit it was extracted from, with the claims and lemmas each change moved. -->

# Changelog

Each spec tag maps to the Core commit it was extracted from.

## Unreleased

- Notice Core (proposed, ADR-081): a new protocol page for the key
  delivery of mailbox cohorts, which is not in the app, extracted from
  Core `3af62982a` (on `main` as `adfb1f7d8`, the same notice code), the
  commit three adversarial reviews last found no
  relay-only alarm, stall or link in. Its claims (forward secrecy of
  update keys, healing after a copy that only reads, convergence under
  a gateway without keys, fixed session counts and sizes) and the
  limits of a copy that writes are in Security Claims; its gateway and
  copy adversaries in Attackers; its key-schedule vectors and 50
  conformance schedules in Test Vectors. Relay A11 documents the four
  cohort actions, off unless `RELAY_COHORT_STORE` is set
  (vauchi/private#1281, core!2412, relay!623).
- In-Person Exchange E9 and step 9 of the sequence: after a question,
  `BTH5` is shown for 10 seconds instead of 3, so the phone that
  answered and started its camera again can still read it; a phone that
  reads its peer's `BTH5` still stops at once (vauchi/private#1330,
  core!2406).
- Link Exchange A10: a repeat link exchange tells the phone that already
  holds the contact that nothing changed, and cannot reconnect two
  people when one phone lost the other (vauchi/private#1285, core
  `14d548a34`).
- Claim S19: meeting again changes a contact's key only after its person
  said yes, to the key of a session the contact's own identity opened;
  the question follows the peer's own statement; the phone that lost the
  contact saves only after that yes. Four lemmas in
  `multistage_exchange.spthy`, each with a control that falsifies it
  (vauchi/private#1285, core!2389).
- In-Person Exchange E1, E7, E8, E9 and the failure table: the confirm,
  done and both frames are `CNF5`, `DON5` and `BTH5`, and their tag's
  label states whether the sender already holds the receiver as a
  contact and how the exchange ended. When one phone holds the other and
  the other no longer holds it, the holder asks its person, for at most
  120 seconds; only a yes gives the contact the new exchange's key, and
  the other phone saves only then. Two phones that still hold each
  other keep their key as before. `CNF4`, `DON4` and `BTH4` are retired
  prefixes. Hover only; Glance keeps B12 (vauchi/private#1285, core
  `e92ea84dd`).
- Claims S1 and S2 name the controls of the card-update model. S1's
  `changes_stay_secret` is falsified by `-DPLAINTEXT_UPDATES`; S1 said
  it had no control. S2's
  `update_comes_from_the_sender_for_this_recipient` is falsified by
  `-DNO_RECIPIENT_BINDING`, and `each_update_is_applied_once` has a
  witness in place of a control,
  `a_leaked_sender_key_applies_one_update_twice`: the prover reaches no
  verdict with the nonce check removed (vauchi/private#950).

- Claim S11 names the test that backs healing after a compromise,
  `a_stolen_state_stops_opening_messages_after_the_device_uses_a_key_made_later`,
  and the window it shows: a stolen ratchet state still opens the
  contact's next message after the device's first reply and nothing
  after the second. The statement said the channel heals at a fresh
  exchange of ephemeral keys; it now says which one. S11 stays partial
  for the two paths without forward secrecy (vauchi/private#950).

- Claims S2 and S9: three `Backed by` sentences named a test without
  its file, or beside another test's file; each now names the file the
  test is in. `check:claim-names` requires that from now on: a name in a
  clause that names files must be in one of them (vauchi/private#950).

- Keys and Cards D1: an identity backup restore registers the install
  as a new device, as a full backup restore does (D4): a random index in
  the upper half of the range, a new signing key and a registry version
  of at least the restore time, naming only the new device. Before, it
  kept the backed-up device index with a fresh key, so contacts that
  pinned that device refused it (vauchi/private#970). The A security
  note no longer says two restored installs share one device index.

- S18 is shipped: Core's `multistage_exchange.spthy` annotates
  `card_authentic`, `peer_accepted_before_save` and `peer_saved_is_true`
  with `@claim: S18` (vauchi/private#1217). The overview counts S1 to S18.

- Card Update and Sync C5 describes Core v0.106.1's bounded wrapper for
  oversized registry controls, missing-registry bootstrap and one
  stateless ACK to the requesting device. Small envelopes and signature
  inputs are unchanged. It states the old-reader limit, the ACK
  forward-secrecy exception and the separate maximum-fleet private-message
  limitation, as implemented in
  [Core!2353](https://gitlab.com/vauchi/core/-/merge_requests/2353).

- Keys and Cards D4: the real payload carries `device_registry`, and a
  full backup restore registers the install as a new device with a
  random index in the upper half of the range and a registry version of
  at least the restore time, keeping the backed-up devices active.
  Before, a restore signed as the backed-up device with a fresh key, so
  contacts that pinned that device refused its card deltas
  (vauchi/private#1247). The A security note now separates the identity
  backup, which still keeps the device index, from the full backup.

- In-Person Exchange gains section E, the multi-stage animated QR of
  Hover and TapHoverShake: a payload signed by the sender's identity
  over its session, a confirm keyed from the transport key only after
  the checks, a done only after the save, a keyed both, and a
  restored contact's rekey only on the peer's verified done. The note that these modes do not yet
  authenticate the peer's identity is gone, B12 points to E8, S17's
  third sentence holds through them, and S18 states the claim
  (vauchi/private#1217). The mode list says the app offers only
  Glance, Hover and Link, so TapHoverShake is deferred.

- In-Person Exchange says the multi-stage modes do not yet authenticate
  the identity key their payload carries, and B12 names the one
  exception A8 and Social Recovery C5 already state (a contact restored
  and waiting takes the exchange's key); S17 says its third sentence
  does not hold through the multi-stage modes (vauchi/private#1217).

- Four sentences stop presenting design as code (vauchi/private#1229):
  Relay says purge is not the only route that carries an identity key
  (the recovery store's `owner_pk` and the guardian store's
  `designator_pk` do too) and keeps no key only for mailbox routing;
  Card Update and Sync's goal names the paths without forward secrecy;
  Social Recovery says rekey offers leave with each sync but no contact
  accepts one yet (C3), and marks the next-identity rotation in person
  as planned. The design that rotation follows is cited by its issue,
  not by a private slug.

- S13 names the decoy payload and that a 6-digit duress PIN is the
  biometric branch only; S14 adds that with biometric unlock the lock
  screen is the same with or without duress, and its tests
  (vauchi/private#1117, ADR-032 amended 2026-11-10).

- Keys and Cards D4: the duress section's credential records
  `password_branch` when duress was set up with two real passwords on a
  device without biometric unlock (vauchi/private#1117, ADR-032 amended
  2026-11-10). It is written only when true, so a biometric-branch
  section is unchanged; a reader from before it refuses a
  password-branch section. D6 and the source list name the
  `backup_recovery/` module.

- Keys and Cards D4 (new; vauchi/private#1117, ADR-080 point 7): the
  full backup is v7, two payloads of one size behind a clear header of
  version, random file id and one salt per payload, each payload bound
  to the whole header. The real payload takes a random slot; the other
  is for the planned decoy payload and is a zero frame under a random
  key until then. A restore derives both keys before trying either.
  From the real profile the snapshot carries the duress section: the
  mask under a transfer key and the app password and duress PIN hashes,
  so a restore locks as before; such a file holds two identities, and
  S13 says what that exposes. D3 (v6) is still imported; the guardian
  backup becomes D5 and what
  the app offers D6. S13 names the v7 vector and its tests. Vectors:
  `backup_v7` added; `backup_v6` kept as recorded.

- Conventions, Versioning: from the first store release a client works
  with clients on the previous Core minor; a wire version change keeps a
  parser for the previous version for one minor, or ships a documented
  migration the previous-release interop lane runs. The table of checks
  names that lane (vauchi/private#1111).
- Link and Relay-Mediated Exchange A: a link needs a six-digit code sent
  another way. Symmetric SPAKE2 keys enter the escrow keys, the responder
  deposits its card only after the sender's deposit, and links gain `v=2`
  (vauchi/private#727). Backs S9.
- Link and Relay-Mediated Exchange A5, A6: the relay answers the same
  escrow deposit again `Stored`; only another blob in a taken slot is
  `AlreadyExists`. A client resends after a 502 the OHTTP relay also gives
  once a put was stored, and that resend had ended the link as
  `link_already_used`. Same bytes, same guess (vauchi/private#727).
- Keys and Cards G3: a link contact is `Remote`, below Standard; device sync
  carries the exchange transport (vauchi/private#727).
- Attackers: the first release's gate is a second operator, as ADR-037's
  addendum of 2026-09-08 sets it. Host separation closes it only for the
  alpha and beta (vauchi/private#1094).
- Social Recovery A11 transport (vauchi/private#796, P33): the hand-back QR
  also holds a per-attempt token. The guardian advertises what derives from
  it, and the phone dials only a match.
- Social Recovery A11 (planned): social recovery restores the same
  identity, from shares guardians hand back in person to a temporary
  recovery key; the seed must derive the claimed key, the phone takes a
  new device index with the lost device revoked in its registry, and a
  share counts once. Section C is compromise rotation only: C3 accepts no
  rekey until the policy guardians' certificate exists, and vouchers,
  guardian tokens and old-key signatures authorize nothing; C5's
  continuation is acted on by none; a contact met in person may rotate
  to the owner's registered next identity on recognition and that
  identity's pinned hash. The Tamarin models allow a single recovery,
  and S16 and S17 say so (vauchi/private#796, P11 to P32).

- Social Recovery A7, B2, C3 to C6: the guardian delivery carries the
  guardian's token and an in-person vouch attaches it; a rekey that is provably the recovered contact's is accepted without asking once the policy guardians' certificate exists; until then every offer is dropped, its proof
  judged without expiry; a contact met again folds the old one; the
  in-person continuation, ratchet kind `0x0e` (Update and Sync, B5); the
  new phone completes with the answer; resends stop after 14 days
  (vauchi/private#796, D18 to D21).

- Social Recovery A10: the new identity restores the backup its
  guardians handed back, keeping its own key and the contacts it has,
  and marks each restored exchanged contact as waiting for its rekey
  (vauchi/private#796).
- Social Recovery A9: the owner may set a recovery passphrase; the
  guardian backup is then sealed once more under an Argon2id key from
  it, so guardians who collude open nothing without it
  (vauchi/private#796, D16).
- Social Recovery A2 and A8: guardian groups are 3 ≤ groups ≤ guardians
  ≤ 9 with no limit on a group's size, chosen by the owner as each
  guardian is added, and the guardian backup is split over them; a
  guardian's database keeps an HMAC of its owner, never the id
  (vauchi/private#796, D15, D17).
- Social Recovery A5: the hand-back starts by itself as the meeting's
  exchange completes, stays owed until the guardian can send, and goes
  once (vauchi/private#796).
- Social Recovery A5 and Update and Sync B5: in the recovery meeting a
  guardian hands its share and the backup back as `0x0d` pieces, only to
  the new key of a claim it vouched for, within 192 hours; a duress
  session answers as holding nothing (vauchi/private#796).
- Social Recovery A8: a changed guardian backup is sent again at most
  once a day, never from a duress session (vauchi/private#796).
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
