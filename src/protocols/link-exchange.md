<!-- SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Link and Relay-Mediated Exchange

> **Status: not yet extracted.** This chapter is a placeholder with its sources listed. It makes no normative statement yet; the claims it will back are S9.

## Goal

Exchanging cards without being in the same place: a link opened by the recipient, or a short code with a six-digit comparison through the relay.

## Actors

*To be extracted.*

## Message flow

*To be extracted.*

## Normative operations

*To be extracted from the sources below, each operation naming its function.*

## State machine

*To be extracted.*

## Failure cases

*To be extracted.*

## Security considerations

Claims backed by this chapter: [S9](../claims.md)

## Vectors

*To be listed from [Test Vectors](../vectors.md).*

## Sources

- `vauchi-core/src/exchange/link_mode.rs` (link URL `https://vauchi.app/x#pk=..&n=..`, bootstrap signed over `vauchi-link-bootstrap-v2`, shared key info `vauchi-link-shared-key-v1`, 7-day TTL)
- `vauchi-core/src/exchange/escrow.rs` (gate, slot and card-key derivations `vauchi-escrow-*-v1`)
- `vauchi-core/src/api/vauchi/import.rs` `complete_link_exchange`
- `vauchi-core/src/exchange/relay_exchange.rs` (short code, `derive_sas` over `vauchi-relay-exchange-sas-v1`)
- `vauchi-core/verification/link_exchange.spthy` (Core round 8: `contact_only_after_approval` falsified today, verified with the owner's PIN design)
