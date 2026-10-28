<!-- SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Disclosure Policy

> **Draft for the maintainer's approval.** The scope and the safe-harbour
> wording below are proposed text; until the maintainer approves them
> here and publishes `security.txt`, the binding instruction is: write to
> security@vauchi.app.

## Contact

- Email: **security@vauchi.app**
- `security.txt`: to be published at `https://vauchi.app/.well-known/security.txt`
  (proposed content in this repository at `src/.well-known/security.txt`).

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
if it maps to one, and whether you want to be named. Encrypted mail is
welcome; the key is published with `security.txt`.

## What to expect

A reply from the maintainer. There is no bug bounty; the project says
so rather than promising one. Findings are fixed in the open, credited
if you wish, and listed in the changelog of this book and on the docs
site's previous-analysis page.

## Safe harbour (proposed)

Research conducted in good faith, within the scope above, against your
own identities and test data, without degrading the service for others
and without exfiltrating data that is not yours, is authorised. The
project will not pursue legal action for such research and will not
report it to law enforcement. If a third party does, the project will
say that the research was authorised.
