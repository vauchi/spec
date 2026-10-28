<!-- SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# In-Person Exchange

> **Status: not yet extracted.** This chapter is a placeholder with its sources listed. It makes no normative statement yet; the claims it will back are S6, S7, S8.

## Goal

Two people in the same place exchange cards over QR codes, with Bluetooth or NFC carrying the bulk, and end with a shared key bound to both identities.

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

Claims backed by this chapter: [S6](../claims.md), [S7](../claims.md), [S8](../claims.md)

## Vectors

*To be listed from [Test Vectors](../vectors.md).*

## Sources

- `vauchi-core/src/exchange/session.rs` (the symmetric QR key agreement, info `vauchi-x3dh-symmetric-v2` over both identity and ephemeral keys in sorted order)
- `vauchi-core/src/exchange/x3dh.rs` (the two-DH agreement the code calls X3DH, info `vauchi-x3dh-key-v2`)
- `vauchi-core/src/exchange/reciprocity_tokens.rs`, `ble_advertisement.rs`, `ble_handshake.rs`, `nfc_handshake.rs`
- `vauchi-core/verification/qr_exchange.spthy`, `reciprocity.spthy`, `ble_advertisement.spthy`, `ble_handshake.spthy`
