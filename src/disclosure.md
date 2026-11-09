<!-- SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Disclosure Policy

## Contact

- Email: **security@vauchi.app**
- PGP: <https://vauchi.app/.well-known/pgp-key.txt>, fingerprint
  `4347 B1C6 57A3 97E5 206E 4709 A84E 1AAB D783 0274` (`security.txt`
  carries the same fingerprint as `openpgp4fpr:`). The encryption
  subkey lives on the maintainer's hardware tokens only; no agent,
  server or CI job can decrypt a report. Reports in clear are read too;
  say so and the reply offers another channel.
- `security.txt`: published at
  <https://vauchi.app/.well-known/security.txt>. Its Policy field points
  at the short form in the workspace's `SECURITY.md` until this book is
  served at spec.vauchi.app; this page is the canonical text and the
  short form defers to it.

## Scope

In scope: everything this book specifies and the code it is extracted
from, [vauchi/core](https://gitlab.com/vauchi/core),
[vauchi/relay](https://gitlab.com/vauchi/relay) and the apps that embed
Core, plus the public relay at its published address when tested with
your own identities only.

Out of scope: the production relay's availability (no load or denial
of service testing), other people's data or identities, the website and
documentation hosting, and social engineering of the maintainer or
users.

## What to send

What you found, how to reproduce it, which claim (S-number) it breaks
if it maps to one, and whether you want to be named. Encrypt to the
key under *Contact* when you can.

## What to expect

A reply from the maintainer within 48 hours and an initial assessment
within 7 days. There is no bug bounty; the project says so rather than
promising one.

Findings rated low or medium are fixed in the open. Findings rated
high or critical (a numbered claim broken under conditions an attacker
can create) are fixed privately and published together with the
release that fixes them, so users are not exposed before an update
exists. Either way the fix is credited if you wish and listed in the
changelog of this book and on the docs site's previous-analysis page;
findings rated medium or above also get a CVE.

## Safe harbour

Research conducted in good faith, within the scope above, against your
own identities and test data, without degrading the service for others
and without exfiltrating data that is not yours, is authorised. The
project will not pursue legal action for such research and will not
report it to law enforcement. If a third party does, the project will
say that the research was authorised.
