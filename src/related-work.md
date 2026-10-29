<!-- SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Related Work

Every mechanism in this book has prior art. Vauchi's contribution, if
it has one, is the combination: a contact card that a person owns,
updates for everyone who holds it without an account or a server that
can read it, delivered through mailboxes that no identity names, and
recoverable through the people who hold it. This chapter names the
closest systems for each part, says where Vauchi matches them, where it
differs, and where it is weaker. Statements about other systems are
taken from their own published specifications or audit reports, listed
under *Sources*; a reader who finds one wrong is asked to report it
like any other error in this book.

## In-person key agreement: Briar's BQP

Briar's Bramble QR Code Protocol is the nearest design to the mutual QR
exchange of [In-Person Exchange](protocols/in-person-exchange.md)
section A. Two devices show QR codes and scan each other; each code
carries a commitment to an ephemeral public key and connection details
for a short-range transport; the keys are then exchanged over that
transport, checked against the commitments, and combined into a master
key. Briar's app and protocol were reviewed by Cure53 in March 2017.

- **Same.** Both sides scan, both contribute a fresh key, and the
  camera is the authenticated channel.
- **Different.** Vauchi's QR carries the keys themselves, signed by
  the identity key, not a commitment, and the session key binds both
  identity keys and both ephemeral keys in sorted order (A4,
  claim [S6](claims.md)). The exchange ends in a persistent contact
  whose card later updates; Briar's ends in a contact for messaging.
- **Weaker or untested.** Briar's protocol has had an external audit;
  Vauchi's has not ([Security Claims](claims.md), *Not claimed*). Vauchi adds tiers Briar does
  not have, a one-QR-then-Bluetooth path (B) and NFC (C), each with
  its own limits stated in that chapter.

## Code-based exchange: Magic Wormhole

Magic Wormhole lets two people who share a short spoken code, such as
`7-crossover-clockwork`, set up an encrypted channel through a mailbox
server. The code is the input to SPAKE2, a password-authenticated key
exchange: the server, or anyone else, gets one online guess per code
and learns nothing it can test offline. The channel ends with the
transfer.

Vauchi's relay-mediated exchange
([Link and Relay-Mediated Exchange](protocols/link-exchange.md)
section B) looks similar and is not the same mechanism.

- **Different, and weaker.** Vauchi's six-digit code is a rendezvous,
  not a secret: the relay sees both payloads and the code, and
  protection against a substituted key rests on the two people
  comparing a six-digit SAS aloud (B4). A skipped comparison is no
  better than a link exchange. Wormhole's design needs no comparison
  step, because the code itself authenticates.
- **Different purpose.** The result is a lasting contact with a
  ratchet, not a one-time channel.

A PAKE over the spoken code is the obvious improvement here and an open
question for this design, not a solved one.

## Identifier-free delivery: SimpleX

SimpleX Chat has no user identifiers: each contact pair communicates
through its own unidirectional queues on relay servers, with separate
send and receive credentials, and the client rotates those queues with
its contacts. With two-hop routing, the first server sees the sender's
address and the second the recipient's.

- **Same.** Vauchi's relay addresses mailboxes by tokens, never by an
  identity, and the tokens change: claim [S4](claims.md),
  [Relay](protocols/relay.md).
- **Different.** Vauchi's tokens are derived from each contact
  pair's shared key and the day (Relay, mailbox tokens), so both sides
  rotate without exchanging a message; SimpleX rotates queues by
  protocol messages. Vauchi has a persistent identity key per person,
  which contacts know and which signs cards; SimpleX deliberately has
  none.
- **Weaker.** Vauchi's derived tokens are not forward secure: whoever
  holds a shared key can compute that pair's past and future tokens
  (Relay, security considerations). Until the first release one
  operator runs both of Vauchi's relay hops, so the two-hop separation
  SimpleX describes is a design here, not yet an operational fact
  (claim [S3](claims.md), partial). Three relay routes, for guardian
  sets, recovery proofs and purges, are addressed by an identity key or
  its hash ([S4](claims.md), partial).

## Accounts without phone numbers: Session

Session needs no phone number or e-mail: an account is a key pair, and
the Session ID shown to users is the long-term public key. Messages
travel through onion requests across a network of service nodes; for an
offline recipient the sender finds the swarm that stores the message
from a deterministic mapping of the recipient's public key.

- **Same.** No phone number, no e-mail, no account on a server.
- **Different.** The two designs route in opposite ways: Session
  stores messages under the recipient's public key, Vauchi never
  routes mailbox traffic by a public key (S4).

## Self-updating address books: Plaxo

Plaxo, launched in 2002 and shut down at the end of 2017, kept each
person's entry on its own servers so that a change one person made
appeared in the address books of everyone who held them. The idea is
Vauchi's central feature, and it is twenty years older than Vauchi.

- **Different.** Plaxo's servers held every card in the clear and
  matched contacts by address book upload, which in 2004 drew criticism
  for updating entries nobody had opted into. Vauchi's relay stores
  only ciphertext ([S1](claims.md)), a card reaches only contacts made
  by an explicit exchange, and which fields each contact sees is chosen
  by its owner ([Keys and Cards](protocols/keys-and-cards.md)).

## Recovery through other people: social-recovery wallets

Wallets such as Argent (2020) let a user name guardians who can approve
moving an account to a new key, with a delay in which the owner can
cancel a hijack. Vitalik Buterin's January 2021 essay "Why we need wide
adoption of social recovery wallets" argued for the model at large.

- **Same.** Guardians chosen in advance, a threshold, and no password
  ([Social Recovery](protocols/social-recovery.md) section A,
  [S17](claims.md)).
- **Different.** A wallet's guardians approve a key change on a shared
  ledger. Vauchi has no ledger: guardians hold Shamir shares of a backup
  key, sealed to them, and the contacts who did not act as guardians
  must each decide whether a new identity is the same person, which is
  why recovery vouching (section B) and acceptance ([S16](claims.md))
  exist at all. Most of what follows for old contacts is open work
  (section C).

## What this leaves

None of the parts above is new. What this book claims, and asks
reviewers to attack, is that the combination holds together: a card
that updates for its holders through a relay that cannot read it, under
tokens that name no one, made by an exchange that binds both identities,
and recoverable through the same people. Where a part is weaker than
the system it resembles, this chapter says so, and
[Security Claims](claims.md) marks the claim partial.

## Sources

- Briar: [Bramble QR Code Protocol, version 4](https://code.briarproject.org/briar/briar-spec/-/raw/b8c4399789a56a094222aa9b539ed04b29040851/protocols/BQP.md);
  Cure53, [Pentest-Report Briar Project App & Protocol 03.2017](https://cure53.de/pentest-report_briar.pdf).
- Magic Wormhole: [documentation, Welcome](https://magic-wormhole.readthedocs.io/en/latest/welcome.html).
- SimpleX: [SimpleX Messaging Protocol overview](https://github.com/simplex-chat/simplexmq/blob/stable/protocol/overview-tjr.md).
- Session: [Onion requests and message routing](https://docs.getsession.org/session-network/session-protocol/onion-requests-and-message-routing);
  [Session litepaper](https://getsession.org/litepaper/pdf).
- Plaxo: [Wikipedia, Plaxo](https://en.wikipedia.org/wiki/Plaxo);
  [Loose Wire, In Plaxo-land, There's Still Some Confusion (2004)](https://www.loosewireblog.com/2004/01/in_plaxoland_th.html).
- Social-recovery wallets: Vitalik Buterin,
  [Why we need wide adoption of social recovery wallets (2021)](https://vitalik.eth.limo/general/2021/01/11/recovery.html);
  [TechCrunch on Argent (2020)](https://techcrunch.com/2020/05/18/buzzy-ethereum-wallet-app-argent-comes-out-of-stealth).
