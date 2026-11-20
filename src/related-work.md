<!-- SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- description: Prior art for each part of Vauchi's design: the closest systems for contact cards, mailboxes and recovery, where Vauchi matches them, differs or is weaker. -->

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

## Messaging cryptography: the Signal protocols

Vauchi's message layer uses the Double Ratchet that Signal specified:
after the first agreement every card update is encrypted under keys
that ratchet forward ([Card Update and Sync](protocols/update-and-sync.md),
claim [S11](claims.md)). Its key agreements are not Signal's X3DH,
although the code names them `x3dh`. X3DH combines the initiator's
identity key and a fresh key with the responder's identity key, a
signed prekey and an optional one-time prekey, three or four
Diffie-Hellman values in all, so that a sender can start a session with
a recipient who is offline.

- **Different.** Vauchi has no prekeys and no prekey server: every
  agreement happens while both people take part. The relay-mediated
  exchange computes two Diffie-Hellman values, long-term exchange key
  against long-term exchange key and fresh key against long-term
  exchange key ([Link and Relay-Mediated Exchange](protocols/link-exchange.md)
  B2); the in-person exchange computes one, between two fresh keys,
  with both identity keys in the HKDF `info`
  ([In-Person Exchange](protocols/in-person-exchange.md) A4).
- **Weaker or untested.** The first message of a session and every
  device-to-device sync batch have no forward secrecy (S11, partial).

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
- **Different.** Vauchi's QR carries no commitment: it holds the
  Ed25519 identity key and a fresh X25519 key in the clear, with an
  Ed25519 signature by the identity key over the payload (A1). The
  Diffie-Hellman is between the two fresh keys only; the identity keys
  enter through the HKDF `info`, next to both fresh keys, each pair in
  sorted order (A4, claim [S6](claims.md)). The exchange ends in a persistent contact
  whose card later updates; Briar's ends in a contact for messaging.
- **Weaker or untested.** Briar's protocol has had an external audit;
  Vauchi's has not ([Security Claims](claims.md), *Not claimed*).
  Vauchi adds tiers Briar does not have, a one-QR-then-Bluetooth path
  (B) and NFC (C), each with its own limits stated in that chapter.

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
  comparing the full authentication fingerprint (B4). A skipped
  comparison is no better than a link exchange. Wormhole's design needs no comparison
  step, because the code itself authenticates.
- **Different purpose.** The result is a lasting contact with a
  ratchet, not a one-time channel.

A PAKE over the spoken code is the obvious improvement here and an open
question for this design, not a solved one.

## Verified contact by invite: Delta Chat's SecureJoin

Delta Chat's Setup Contact protocol verifies two people's OpenPGP keys
over e-mail, which the attacker may control, using a QR code as the one
channel the attacker cannot see. The code carries the inviter's key
fingerprint, the address, a single-use invite number and a second
secret, `AUTH`; the joiner checks the key that arrives against the
fingerprint, and the inviter accepts the joiner only on an encrypted
message that carries `AUTH`.

- **Same.** Vauchi's link exchange follows the same pattern: the link
  is the out-of-band channel, it carries the initiator's fresh key and a
  nonce from which the relay slots derive, and the relay in between may
  be hostile ([Link and Relay-Mediated Exchange](protocols/link-exchange.md)
  section A).
- **Different.** Delta Chat's transport is ordinary e-mail between
  addresses both sides already have; Vauchi's is a relay that holds
  sealed slots for a short time and learns no address.
- **Weaker or untested.** A link and its code sent over one channel the
  attacker reads give the attacker the exchange; the chapter says so, and
  the claim for link exchanges is partial ([S9](claims.md)).

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

## Hiding who writes to whom: sealed sender and Pond

Signal's sealed sender (2018) removes the sender from what the service
sees: a message carries a short-lived sender certificate inside the
encryption, so only the recipient reads who sent it. To limit abuse a
sender must prove knowledge of a 96-bit delivery token that the
recipient derives from its profile key, which in practice confines
sealed messages to contacts. The service still needs the recipient to
deliver, and Signal names resistance to correlation by timing and IP
address as work still in progress. Pond, a 2013 design by Adam Langley
now "in stasis", used BBS group signatures for a related aim: to let
servers reject messages from non-contacts without the server being able
to identify those contacts.

- **Same.** Vauchi's relay record carries no sender: the sender is
  authenticated inside the ciphertext, by the recipient
  ([Relay](protocols/relay.md) A2, claim [S2](claims.md)). Depositing
  needs the recipient's mailbox token, which only a contact can derive,
  so the token plays the part of Signal's delivery token and Pond's
  group membership.
- **Different.** The recipient side is hidden as well: Signal's service
  knows which account a message is for, Vauchi's relay sees only a token
  that changes daily ([S4](claims.md)).
- **Weaker or untested.** The relay still sees which tokens receive how
  much, and when; padding and the delayed path reduce this, and the
  claims chapter says they do not remove it (*Not claimed*), and the
  relay can still correlate one fetcher's requests of a day by their
  timing on the immediate path. Vauchi's defence against an observer of
  addresses is the OHTTP relay pair, run by one operator until the first
  release ([S3](claims.md); [Attackers](attackers.md)).

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
- **Weaker or untested.** Nothing beyond what holds for every row of
  this chapter: Vauchi has no external audit, and the three
  identity-keyed relay routes listed under SimpleX apply here too.

## In-person verification: PGP key signing and the web of trust

Key-signing parties made in-person fingerprint checks the basis of
OpenPGP trust long before smartphones: people compare fingerprints,
then certify each other's keys. In the web of trust that follows, those
certifications are transitive: GnuPG treats a key as valid when it is
certified by one fully trusted introducer, or by three marginally
trusted ones, by default.

- **Same.** Trust starts from meeting: Vauchi's highest trust comes
  from an in-person exchange whose keys the camera, the proximity check
  or a fingerprint comparison bound to the person in front of you.
- **Different.** Vauchi's trust does not travel. A contact's trust
  level is derived from how that one exchange happened, and nothing a
  third person signs raises it ([S10](claims.md)). The one place where
  contacts speak for one another is recovery vouching, and there a
  voucher says only that an old key and a new key are the same person
  ([Social Recovery](protocols/social-recovery.md) section B).

## Names: Zooko's triangle and petnames

Zooko Wilcox-O'Hearn observed that names cannot be global, secure and
memorable all at once. Marc Stiegler's petname systems (2005) answer by
keeping three kinds of name apart: the key, which is secure and global;
a nickname the key's owner proposes, which helps discovery; and a
petname, a private name the user gives the key, which is memorable and
binding only for that user.

- **Same.** Vauchi follows the same split. A contact is its identity
  key; the display name on the card is the owner's proposal, which the
  QR and the card carry ([In-Person Exchange](protocols/in-person-exchange.md)
  A1, [Keys and Cards](protocols/keys-and-cards.md) G1); and a user can
  give a contact a local nickname that never leaves the device
  (`vauchi-core` `contact/display.rs`, not yet specified in this book).
- **Different.** Vauchi has no global name and no lookup by name at all:
  a key becomes a contact only through an exchange, never by search.

## Self-updating address books: Plaxo

Plaxo, launched in 2002 and shut down at the end of 2017, kept each
person's entry on its own servers so that a change one person made
appeared in the address books of everyone who held them. The idea is
Vauchi's central feature, and it predates Vauchi by twenty-four years.

- **Different.** Plaxo's servers held every card in the clear and
  matched contacts by address book upload, which in 2004 drew criticism
  for updating entries nobody had opted into. Vauchi's relay stores
  only ciphertext ([S1](claims.md)), a card reaches only contacts made
  by an explicit exchange, and which fields each contact sees is chosen
  by its owner ([Keys and Cards](protocols/keys-and-cards.md)).

## Local-first software

Ink & Switch's 2019 essay "Local-first software" (Kleppmann, Wiggins,
van Hardenberg, McGranaghan) asked that data live on the user's
devices, work offline, sync across them, outlive the vendor and stay
under the user's control. Vauchi follows that line: the card and the
contact list live on the devices, the relay holds sealed blobs for a
bounded time, and devices of one identity sync among themselves.

- **Different.** The essay's main tool is the CRDT, for data that
  several people edit together. Vauchi has nothing of the kind: a card
  has one author, and updates are ordered by per-device version floors
  ([Card Update and Sync](protocols/update-and-sync.md)).

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

- Signal: [The X3DH Key Agreement Protocol](https://signal.org/docs/specifications/x3dh/);
  [The Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/).
- Briar: [Bramble QR Code Protocol, version 4](https://code.briarproject.org/briar/briar-spec/-/raw/b8c4399789a56a094222aa9b539ed04b29040851/protocols/BQP.md);
  Cure53, [Pentest-Report Briar Project App & Protocol 03.2017](https://cure53.de/pentest-report_briar.pdf).
- Magic Wormhole: [documentation, Welcome](https://magic-wormhole.readthedocs.io/en/latest/welcome.html).
- SimpleX: [SimpleX Messaging Protocol overview](https://github.com/simplex-chat/simplexmq/blob/stable/protocol/overview-tjr.md).
- Delta Chat: [Setup Contact and Verified Group protocols](https://countermitm.readthedocs.io/en/latest/new.html).
- Signal sealed sender: [Technology preview: Sealed sender for Signal (2018)](https://signal.org/blog/sealed-sender/).
- Pond: [agl/pond README](https://github.com/agl/pond).
- Session: [Onion requests and message routing](https://docs.getsession.org/session-network/session-protocol/onion-requests-and-message-routing);
  [Session litepaper](https://getsession.org/litepaper/pdf).
- Petnames: Marc Stiegler, [An Introduction to Petname Systems (2005)](http://www.skyhunter.com/marcs/petnames/IntroPetNames.html),
  which states Zooko's triangle and cites Zooko's original note.
- Plaxo: [Wikipedia, Plaxo](https://en.wikipedia.org/wiki/Plaxo);
  [Loose Wire, In Plaxo-land, There's Still Some Confusion (2004)](https://www.loosewireblog.com/2004/01/in_plaxoland_th.html).
- OpenPGP web of trust: GnuPG manual,
  [`--completes-needed`, `--marginals-needed`](https://www.gnupg.org/documentation/manuals/gnupg/GPG-Configuration-Options.html).
- Local-first: Ink & Switch, [Local-first software (2019)](https://www.inkandswitch.com/essay/local-first/).
- Social-recovery wallets: Vitalik Buterin,
  [Why we need wide adoption of social recovery wallets (2021)](https://vitalik.eth.link/general/2021/01/11/recovery.html);
  [TechCrunch on Argent (2020)](https://techcrunch.com/2020/05/18/buzzy-ethereum-wallet-app-argent-comes-out-of-stealth).
