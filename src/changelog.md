<!-- SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Changelog

Each spec tag maps to the Core commit it was extracted from.

## Unreleased

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
