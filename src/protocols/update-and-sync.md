<!-- SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Card Update and Sync

> **Status: not yet extracted.** This chapter is a placeholder with its sources listed. It makes no normative statement yet; the claims it will back are S1, S2, S5, S11.

## Goal

How a changed card reaches every contact and every own device: envelopes, the Double Ratchet, ordering, replay and rollback resistance, padding, and what forward secrecy holds where.

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

Claims backed by this chapter: [S1](../claims.md), [S2](../claims.md), [S5](../claims.md), [S11](../claims.md)

## Vectors

*To be listed from [Test Vectors](../vectors.md).*

## Sources

- `vauchi-core/src/crypto/ratchet.rs` and `chain.rs` (`Vauchi_Root_Ratchet`, `Vauchi_Chain_Key`, `Vauchi_Message_Key`)
- `vauchi-core/src/exchange/ratchet_bootstrap.rs` (both sides seed the ratchet with fresh keys)
- `vauchi-core/src/sync/delta.rs` (`vauchi-delta-v3`), `sync/device_sync.rs`
- `vauchi-core/verification/card_update.spthy`
