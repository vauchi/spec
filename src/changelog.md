<!-- SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Changelog

Each spec tag maps to the Core commit it was extracted from.

## Unreleased (towards 0.1-draft)

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
