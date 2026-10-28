<!-- SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Social Recovery

> **Status: not yet extracted.** This chapter is a placeholder with its sources listed. It makes no normative statement yet; the claims it will back are S16, S17.

## Goal

Recovering a lost identity through helpers who vouch and guardians who hold shares: thresholds, what guardians learn, collusion bounds, and the rekeying of old contacts.

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

Claims backed by this chapter: [S16](../claims.md), [S17](../claims.md)

## Vectors

*To be listed from [Test Vectors](../vectors.md).*

## Sources

- `vauchi-core/src/recovery/mod.rs` (claims, vouchers, proofs, `verify_for_contact`), `recovery/guardian.rs`, `recovery/sealed_box.rs`
- `vauchi-core/src/backup/key_shard.rs`, `guardian_groups.rs`, `crypto/shamir.rs` (Kani proofs in `shamir_proofs.rs`)
- `vauchi-core/verification/recovery_acceptance.spthy`, `social_recovery.spthy`
- Open work: online rekeying after recovery (vauchi/private#796; plan steps 1 to 9)
