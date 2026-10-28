<!-- SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Changelog

Each spec tag maps to the Core commit it was extracted from.

## Unreleased (towards 0.1-draft)

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
