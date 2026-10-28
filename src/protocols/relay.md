<!-- SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Relay

> **Status: not yet extracted.** This chapter is a placeholder with its sources listed. It makes no normative statement yet; the claims it will back are S3, S4.

## Goal

The keyless relay: mailbox tokens, Oblivious HTTP, what the relay stores, and exactly what it learns: timing, sizes and mailbox counts.

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

Claims backed by this chapter: [S3](../claims.md), [S4](../claims.md)

## Vectors

*To be listed from [Test Vectors](../vectors.md).*

## Sources

- `vauchi-core/src/network/mailbox_token.rs` (`Vauchi_Mailbox_v1`, `Vauchi_MailboxDevice_v1`, `Vauchi_DeviceSyncRecipient_v1`, day epoch)
- `vauchi-core/src/network/http_transport/` (OHTTP, RFC 9458)
- `vauchi/relay` `src/http_api.rs` (128 KB body limit), `guardian_storage.rs`
- `vauchi-core/verification/mailbox_token.spthy` (Core round 8, diff-equivalence across days)
