<!-- SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Vauchi Protocol Specification

**Version**: 0.1-draft, in preparation. Nothing here is final; drafts
are published because reviewers prefer breaking drafts to admiring
monuments.

Vauchi is a privacy-focused contact card: people exchange cards in
person, the cards update automatically through a relay that cannot read
them, and there is no account. This book specifies the protocols that
make those statements true, as the code implements them today.

## What this book is

- **Normative, by extraction.** Every chapter describes what
  [vauchi-core](https://gitlab.com/vauchi/core) and
  [vauchi/relay](https://gitlab.com/vauchi/relay) do on `main`, with
  the source file named. Where the code and the intended design
  differ, the chapter says what the code does and names the issue.
- **Falsifiable.** The [claims](claims.md) are numbered S1 to S17.
  Each states its attacker, the exact statement, what it would mean if
  it were false, and the test, lemma or lane that backs it. That
  chapter is the invitation: it says where to swing.
- **Checked.** The [test vectors](vectors.md) are produced by the
  shipped functions and verified by Core's test suite, and the
  [wire schemas](schemas.md) are generated from the wire types with the
  parser's bounds proved against it; CI fails when a copy here differs
  from Core's or an example stops validating.
- **Honest about absences.** A two-DH key agreement that the code
  calls X3DH, a SPAKE2 library no one has audited, the relay's view of
  timing: each is written down where it belongs.

## How to read it

Every protocol chapter has the same shape: goal, actors, message flow,
normative operations, state machine, failure cases, security
considerations, vectors. Chapters are ordered the way a reviewer will
attack them. Each chapter's status line names the commits it was
extracted from; a chapter marked *not yet extracted* would be a
placeholder with its sources listed and make no claim.

Related: the plain-language pages at
[vauchi.app/docs](https://vauchi.app/docs/security/), the Tamarin,
Quint and Kani models in Core's `verification/` directories, and the
[disclosure policy](disclosure.md) for reporting what you find.
