<!-- SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Keys and Cards

> **Status: not yet extracted.** This chapter is a placeholder with its sources listed. It makes no normative statement yet; the claims it will back are S10, S12, S13, S14, S15.

## Goal

The key hierarchy from one master seed, per-device keys, the storage hierarchy, backups, duress, and the card format with its canonical encoding and field visibility.

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

Claims backed by this chapter: [S10](../claims.md), [S12](../claims.md), [S13](../claims.md), [S14](../claims.md), [S15](../claims.md)

## Vectors

*To be listed from [Test Vectors](../vectors.md).*

## Sources

- `vauchi-core/src/identity/mod.rs` and `identity/device.rs` (Ed25519 key is the seed; `Vauchi_Exchange_Seed_v2`, `Vauchi_Device_ID_v2`, `Vauchi_Device_Exchange_v2`)
- `vauchi-core/src/crypto/shredding.rs`, `cek.rs`, `encryption.rs` (XChaCha20-Poly1305 tagged format), `padding.rs`
- `vauchi-core/src/backup/full_backup.rs` (v3 and v5 formats, Argon2id then HKDF `vauchi-backup-v3`)
- `vauchi-core/src/card/` (card and field model, visibility default-hidden)
- `vauchi-core/src/contact/trust.rs` (trust levels derived from exchange facts)
- `vauchi-core/verification/duress_cover.spthy`, `device_link.spthy`; `vauchi-app/verification/device_link_machines.qnt`
