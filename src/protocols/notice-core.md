<!-- SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- description: The proposed key delivery of mailbox cohorts: what two devices promise each other, and the derivations, records, stored state, sessions and slots that keep those promises. -->

# Notice Core (proposed)

> **Status: proposed (ADR-081), not in the app.** Extracted from
> `vauchi/core` `3af62982a`, where it is implemented in `vauchi-core`
> behind the `notice-core` feature and wired to nothing: no path of the
> app calls it. The relay's cohort actions ([Relay](relay.md) A11)
> exist but are off unless `RELAY_COHORT_STORE` is set. The promises
> below are reviewed claims about a proposed design, not shipped
> properties; [Security Claims](../claims.md#notice-core-proposed)
> states them. A human cryptographer reviews the design before release.

The notice core is the key-delivery part of mailbox cohorts: how a
device that edits its card gets the key of the new card to each
contact device, through slots that every member of a cohort writes and
reads alike.

Part one (sections A to F) says what two devices promise and do. Part
two (sections 1 to 9) says it byte for byte and step by step. Rule
labels (R1, S2, B1) are part one's. Where the two differ, part two
governs the bytes and the order, and part one the promises.

---

## Part one: promises and rules

## A. Setting

Vauchi users exchange contact cards in person and keep them up to date
through relays. Each pair of devices that exchanged cards shares a
session from that exchange. When a user edits their card, each contact
device must get the new card.

- **Cohort.** Devices are grouped into mailbox cohorts of a few hundred.
  In every session each device writes the same public number of notice
  slots and of content slots, real or dummy, whatever it has to send,
  and each member downloads every slot of its cohort. A dummy is random
  bytes of the slot's size, so its tag and body look like a real
  record's. What a device does in response to a record it read goes out
  in those same fixed slots, so a response is not visible as extra
  traffic. A device recognises its own records by a 16-byte tag.
- **Records.** A content record is 576 bytes and holds a card update
  encrypted under a fresh update key. The body is the whole card as
  the contact's group sees it, not a difference, and carries inside the
  encryption the sender's identity signature (Ed25519) and a 32-bit
  version that rises with each edit; its handling at the top of its
  range is Core's. A notice is 96 bytes and carries one update key, or
  a control record, from one device to one contact device.
- **Direction.** Everything below is one direction: a sender device S
  that edits a card and a receiver device R, a contact's device. Each
  has a long-term X25519 key the other knows. The reverse direction is
  a separate instance with the roles swapped.
- **Relays.** The outer relay and the application relay (the gateway,
  [Relay](relay.md)) carry the slots. They keep records for 120 days.
- **Time.** A refresh period is seven days. Devices get sessions as
  rarely as every three days, clocks differ by up to three days, and a
  device may be absent for 14 days.
- **Randomness.** Every key (ratchet, ephemeral, update, dummy) is
  drawn from the operating system at the moment it is made. No
  generator state is stored, so a copy cannot predict a later key.

## B. Adversaries and promises

Adversaries:

- **G, the gateway:** the outer relay and gateway colluding. It sees
  every write and read, and may drop, delay, reorder and replay records
  and inject bytes. It holds no device keys.
- **T, a copy:** someone who copied the full state of S or of R once,
  at one moment, and may afterwards read the cohort and write any
  number of records. T does not see state the device creates later.
- **Not defended:** T helped by G; an attacker who copies state again
  and again.

Promises:

- **P1, latest card.** R converges on S's latest card and may skip
  intermediate edits. Where S's slot budget is not full (section E):
  with nothing lost, within two sessions of each device; after a lost
  notice, within one refresh period plus two sessions of each device;
  after lost content, within two refresh periods; after a lost notice
  and lost content together, within about three: a model of 3,000 runs
  of 200 days with sessions one to three days apart found at most 19.3
  days, and 21.9 with clocks set back by up to three days; an absence
  can add a round, and after an outage of more than three periods in
  which a notice chain ran past R's window, an epoch must open first
  (P3's time). Where the notice or content budget is full, records
  queue and the card arrives later. A device whose clock is wrong by
  more than a week receives nothing new until it is right, and a
  sender whose clock ran ahead and was corrected pauses republishing a
  body for as long as it ran ahead.
- **P2, forward secrecy.** Each update has its own key. S deletes it
  when a newer update supersedes it, from its queues too. R deletes a
  notice's key once it has read the notice, keeps an update key at most
  21 days after the last notice that carried it while it waits for the
  content (each view renews it), keeps the key of a position it skipped
  for three refresh periods from the skip, and keeps the means to read
  an epoch's notices for three refresh periods after leaving it. These
  windows add up: an update key read late from a skipped position, an
  epoch left, or a position of the current epoch not read yet can then
  wait 21 days as pending, so a later copy may hold a superseded key
  for both windows together; the last case lasts while R stays in the
  epoch. A notice R has not yet read in its current epoch stays
  readable to a later copy of R until R moves on and three periods
  pass. The keys of refresh and opening addresses do not step; those
  records carry no update key. Outside those windows a later copy of
  either device reads no superseded update from the relays. Every
  window runs on the device's clock and is closed in the device's
  sessions: a clock set back lengthens it by up to the set-back, and
  once corrected may end it up to that much early; a device that runs
  no session keeps what it holds until its next one, up to the relays'
  120 days. R's first act on loading its saved state is to erase what
  has expired, before it reads or writes. S holds no notice key but the
  newest update key, which goes when superseded, and erases epochs
  after a session's refreshes (S4). A copy taken from storage while the
  app has not run holds the keys whose windows ended since its last
  session. The session seed is erased once the seed epoch is derived.
  These windows cover saved state and the protocol's live state, not
  leftovers in freed memory: the HKDF and HMAC crates Core uses (0.12)
  do not wipe their internal state, so a copy of the process's memory,
  a stronger attacker than a copy of storage, may still hold key
  material P2 calls gone.
- **P3, healing.** A copy that only reads loses access to updates made
  afterwards once R has made a refresh after the copy, S has opened it,
  R has named the new epoch and S has followed that name: up to about
  four refresh periods (up to about 23 days with sessions every three
  days, and about 27 when R's clock runs three days ahead at each
  refresh and is corrected after) while both devices have sessions and
  S's budget is not full. A copy of S still recognises the weekly
  publications of a body it already holds until the group is next
  edited; it learns nothing from them except that no edit happened.
  While R makes no refresh, nothing heals. If an older refresh reaches
  S after a newer one, S writes in the older epoch until the next
  refresh (S2); within one session S avoids that by order, so it takes
  the gateway, and a copy the gateway helps is not defended.
- **P4, a copy that writes: best effort.** The alarms of section D are
  raised when a device sees their condition. There is no promise that
  a copy that writes is always alarmed, or that its hold on the
  direction always ends. Three reviews and a red team could not make
  the stronger promise hold; section F lists what a copy that writes
  can still do. A stronger promise is beta work with a human
  cryptographer.
- **P5, no harm without keys.** Honest use and G alone raise no alarm,
  and cannot stop R converging on the latest card once G delivers
  again, while the devices' clocks stay within section A's bounds. A
  clock set back by months, together with a gateway that kept honest
  records far beyond the relays' 120 days, can raise one alarm with no
  key: the sender has forgotten the refresh and the epoch it named.
- **P6, metadata.** G cannot tell a control record from an update
  notice or a dummy, link a direction's records, or learn who writes to
  whom.

An alarm warns the user and delivery goes on; a contact is frozen only
if its device is marked stolen. An alarm stays until the two people
verify each other again.

Outside this layer: a copy of S holds S's identity key, so it can sign
cards as S at any version, and R cannot tell them from S's. That is
impersonation through a stolen identity key, with or without cohorts.

## C. Rules

### Receiver R

- **R1, refresh.** At its first session seven days after the last, R
  makes a fresh `R_m` with the next number `m` and saves it. Every copy
  of the refresh carries the same `R_m`, `m` and name: R's current
  epoch when the refresh was made. Until a session carrying it is
  acknowledged, R seals a copy in its current epoch and one in the
  epoch it left most recently; only the proof key differs between
  them. R keeps the private keys of its newest three refreshes not yet
  used. For every refresh it issued within three refresh periods it
  keeps the number and the key ID; for every such number it used, a
  hash of the `e` it accepted. (It does not tie a refresh to the epochs
  it sealed it in: R2 watches every issued number in every epoch it
  sealed a refresh in, which only a key holder can tell apart.)
- **R2, reading an opening.** R watches the opening addresses of the
  numbers it issued within three refresh periods and of the two
  numbers above its newest, in each epoch it sealed a refresh in
  within that time; the address gives the base. A number above its
  newest, or a key ID that is not the one issued under the number,
  raises its alarm and the opening is ignored. A second opening on a
  number R already used, with a different `e`, raises its alarm and is
  not derived. An opening whose number is not above the current
  epoch's, or on a key R no longer holds, is ignored. Otherwise R
  checks the confirmation; a failure raises its alarm. On success R
  deletes that private key and moves: the new epoch becomes current.
  R derives at most one epoch a refresh, and only moves upwards.
- **R3, what R keeps of an epoch it left.** What it needs to seal
  refreshes there and read openings based on it: for three refresh
  periods after it left the epoch or last sealed a refresh there,
  whichever is later, and while it is the epoch of R's latest alarm
  (R5). What it needs to read update notices there: for three refresh
  periods after leaving.
- **R4, view.** R shows the card with the highest version among content
  whose signature verifies. A notice whose content fails the signature
  is ignored.
- **R5, after an alarm.** Once a record read in epoch X raised R's
  alarm, R also seals its refreshes in X for three refresh periods
  after that alarm, for the most recent such X only: at most three
  copies of a refresh. An alarm queues R's newest refresh again, so it
  goes to every epoch it now needs, X included, without waiting for the
  next refresh; a copy for an epoch R entered after making the refresh
  still names the epoch it named.

### Sender S

- **S1, reading a refresh.** S watches the refresh addresses of every
  epoch it keeps, from 18 weeks back (the relays keep records 120 days)
  to one week ahead, 20 weeks. It tries the proof against the ID of each
  epoch it keeps (the seed included), then against the IDs of epochs it
  erased. The one that verifies is the named epoch. Refreshes read in
  one session are handled in rising order of their number.
- **S2, follow once.** S remembers each refresh it read, with key and
  name, for 20 weeks on its own clock from reading it, at most 64. A
  refresh's addresses are watched to their week plus 18 on the writer's
  clock, so with clocks apart and set back, a copy held back to that
  boundary can read as new for up to about a week. S then opens on a
  number R no longer watches, and may write in an older named epoch
  until R's next refresh; no alarm results. An identical refresh is
  ignored. For a number not remembered, S follows the name: it writes
  from now on in the named epoch. A different key or name under a
  remembered number raises S's alarm and is followed too. The order S
  reads refreshes in is the order it follows them in; a late older
  refresh moves S back until the next one. A refresh naming an epoch S
  opened and has since erased follows nothing and raises nothing; it is
  still handled for opening (section 7, step 3).
- **S3, foreign name.** If the proof verifies against no epoch S keeps
  or erased, S raises its alarm and writes from now on in the epoch
  the refresh was sealed in.
- **S4, opening.** For a refresh number and key it has not handled, S
  opens an epoch with a fresh `e`, saves it, and seals the opening at an
  address of that number in the base epoch, again in later sessions
  until four attempts are made or the epoch is named. `e` is deleted
  once the keys are derived. A direction holds one opening: a higher
  number replaces the queued one, a lower number opens nothing while a
  higher one is queued (section 8). A second key under a number S
  already opened replaces the first, so R's own refresh is not shut out
  by a forged one under the same number, while one of the number's four
  opening addresses in that base is left. A forged refresh with a
  higher number does shut R's refreshes out while its opening is queued
  (section F). Apart from the `m − 3` rule below, S erases no epoch,
  named or not, whose number is not below the highest it has followed a
  name to, nor one that is the base of an opening still queued,
  whatever order the refreshes arrived in and wherever a late older
  refresh made it write: R only moves upwards, so S never erases an
  epoch R may still be in. Below that number an epoch lasts three
  refresh periods from its opening, or from its last naming. Once S has
  opened an epoch on a refresh numbered `m`, it erases, once it has
  read the session's refreshes and before it writes, every epoch still
  unnamed numbered `m − 3` or lower, other than the one it writes in
  and the base of a queued opening, which R can no longer move into: S
  keeps at most three unnamed epochs R can use. An epoch spared as a
  queued base goes in a later session that opens a number at least
  three above it. S handles a refresh by following its name first, then
  opening. The proof key takes the new epoch's root, so R's device key
  and the openings it reads do not give a copy the proof key of a later
  epoch.
- **S5, updates.** Each update has a fresh key, sealed on the notice
  chain of the epoch S writes in. S keeps only each group's latest key.
  Each time S follows a refresh, whether or not the epoch changes, it
  sends the current view in the epoch it writes in: the latest update
  key of each group the contact is in. So a lost update is sent again
  within a refresh period even when no epoch opens. S publishes each
  group's current content again once a refresh period, so lost content
  is replaced too; every transmission of a content record has a fresh
  ID and nonce, so the gateway links neither publications nor resends.
  A card body is at most 3,984 bytes; avatars are not defined here.
  When an edit supersedes a body, S removes what is queued of it and
  erases its key. S assigns at most 128 notice positions to a contact
  device a refresh period, resends included.
- **S6, order.** When slots are short, update notices go first, except
  that every eighth notice slot goes to a control record (an opening or
  a current view) if one is waiting. Heavy editing then slows healing
  but cannot stop it.

### Both

- **B1, a position is read once.** A device erases a position's message
  key when it has read the record there; a second record at that
  position is not recognised. With openings off the chains, comparing a
  second record at a position would detect nothing the other alarms do
  not, and keeping the keys for it would cost forward secrecy and a
  store an honest sender could fill.
- **B2, reading window.** On each chain a device recognises records up
  to 512 positions beyond the lowest it has not stepped past. When it
  reads a record ahead, the positions it skipped keep their message
  keys for three refresh periods from the skip, at most 256 a chain. A
  lost or never-written position delays nothing. A chain that runs
  beyond the window is left behind when the next opening, found at its
  address whatever happened on the chain, moves the direction to a new
  epoch.
- **B3, resends.** A session first assigns each record its position or
  address and advances the counters, then saves the state in one
  transaction, then writes. A record whose session is not
  acknowledged, or is cut by a crash, is sent again with the same
  content at a new position or address, never at one already assigned:
  for a refresh the same key, number and name; for an opening the same
  `e` and confirmation; at most four addresses for an opening, and four
  an epoch and week for a refresh.
- **B4, retention.** R keeps its current epoch whatever its age, and of
  the others what R3 says. S keeps the epoch it writes in and what S4
  says. Counting every named and every not yet named epoch it keeps, at
  most 24 and 12: past those, epochs below the highest number followed
  are erased, the one named longest ago and the lowest number first. Of
  an epoch it erases S keeps the ID (the newest 64), to tell a late
  refresh naming it from a foreign one. A device uses its clock as it
  is; a stored time that lies in the future is set to the clock's time
  when it is next looked at.
- **B5, backups.** Notice state is excluded from backups; a restored or
  replaced device starts new directions.
- **B6, new directions.** When two people verify each other again, both
  directions between their devices start anew from a fresh seed.

## D. Alarms

| Alarm | Raised by |
|---|---|
| an opening on a refresh number not yet issued | R |
| an opening whose key ID is not the one issued under its number | R |
| an opening on a held key whose confirmation fails | R |
| two openings on one refresh number with different `e` | R |
| a different key or name under a refresh number already seen | S |
| two different records that open at one address | S or R |
| a refresh whose proof matches no epoch S opened | S |

An alarm is shown until the two people verify each other again.

## E. Budget

Each device writes 80 notice slots a background session and 40 a tick
while the app is open, shared by all its contacts. The rules above cost
a contact about four control records a week: a refresh sealed twice, an
opening and the current view for one group; each further group the
contact is in adds one: with background sessions only, about 187 notice
slots a week, control records alone fill the budget near 46 contact
devices, and sessions while the app is open carry the rest. One edit
costs one update notice a contact device. A session also writes 5
content slots (2 a tick); a group's body takes 1 to 8, on each edit and
once a week, and when a week's slots do not hold every group's weekly
publication a group waits its turn. The budget is full when a session's
notices do not fit: for example one edit for more than 80 contact
devices, with the app never opened, takes more than one session. A
cohort holds 330 devices within 50 MB a day.

## F. What a copy that writes can still do

Known, from three reviews and a red team. Each needs the copy to write.
Singly most raise an alarm and pass; combined they need not: a copy of
S that writes every chain position first, and answers R's refreshes
itself, can hold the direction for as long as it writes, and after R
alarms inside an epoch only the copy holds, R5 no longer reaches S.

- **Take the sender's writing epoch for a while.** A refresh the copy
  seals under a new number, with its own key and a name it reads, moves
  S there. R's key-ID check alarms when it reads the opening, if the
  number is one R watches (its own and the two above its newest); a
  higher number is not seen by R at all. While the opening on that
  higher number is queued, R's own refreshes are read as handled and
  open nothing, and are not opened later; the copy can repeat it, one
  forged refresh a week, so healing never starts for as long as the
  copy writes, with no alarm. Only re-verifying the contact in person
  ends it.
- **Trap the receiver.** A copy of R opens the refreshes R issued while
  S was away; R moves into the copy's epochs. R's later refreshes reach
  S through R5 only if R saw something that alarmed.
- **Hide a record.** A copy of S that writes at a notice-chain
  position before S does is read, and S's record there is not; the
  weekly current view replaces it. A copy that writes at an address
  first is read first, and the honest record there then raises the
  alarm.
- **Spend resources.** Each refresh the copy seals costs S a proof
  search and an opening; more than 12 unanswered ones push out the
  epochs with the lowest numbers, a copy of S's notices can push out
  R's pending update keys (32 a direction), and S2's table is bounded,
  so what it forgets is no longer checked.
- **Shorten what the sender keeps.** A copy of R that seals a refresh
  under a very high number with its own key, and then names the epoch
  S opens on it, sets the highest number S has followed. Every epoch
  below it then lasts three periods only, also after the copy stops.
- **Go unnoticed after a loss.** An alarm depends on a record being
  read; if that record is lost, nothing is raised.
- **Cut the receiver off in an epoch.** A copy of S that writes far
  ahead on a notice chain makes R give up the positions S really uses
  (B2), until the direction moves to a new epoch.

The gateway alone can do three lesser things: drop or delay records,
which delays the card until the next refresh period brings the view,
the content and an opening again; deliver an older refresh after a
newer one, which moves S back for up to a refresh period with no alarm
(S2); and replay records, which are dropped (B1 and the address
hashes).

---

## Part two: the protocol

## 1. Notation

- `‖` is concatenation. Integers are big-endian and unsigned; `(n)`
  after a field is its length in bytes. `[:n]` is the first `n` bytes.
- `HKDF(salt, ikm, info, n)` is HKDF-SHA256 (RFC 5869) with `n` output
  bytes. `HMAC` is HMAC-SHA256. `H` is SHA-256.
- `DH(a, B)` is X25519 as in RFC 7748. A DH result of 32 zero bytes is
  invalid. No other check is made on a public key.
- A **device key** is the X25519 key pair ADR-064 gives each device for
  its sessions. `label = sender device public key (32) ‖ receiver
  device public key (32)`, stored with the direction and never
  recomputed. It names the direction.
- A period is 604,800 seconds. "Three periods" is 1,814,400.
- **Clock.** A device uses its system clock as it is. `week(t) =
  floor(t / period)` on Unix time, as 4 bytes. A stored time that lies
  in the future of the clock is set to the clock's time when it is
  next looked at; ages are measured from stored times. While a clock
  is set back, every retention window is longer by up to the set-back.
  A stored time pulled back to it stays back, so once the clock is
  corrected, the windows of the times pulled back end up to that much
  early. Something kept "for" a duration is gone once its age is equal
  to the duration or more. A device does all of this in its own
  sessions only. Two devices whose clocks differ by more than a week do
  not find each other's control records or content until the clock is
  right; nothing is raised and nothing is lost that the next refresh
  does not send again.
- Every key is drawn from the operating system's generator when it is
  made. No generator state is stored.

## 2. Derivations

An **epoch** is a set of chains for one direction. The seed epoch comes
from the session the two devices share. Every later epoch is opened by
S on a refresh from R.

**Seed.** In the seed handshake each device sends a fresh X25519 public
key through the Core session, once for each direction; both handshake
private keys are erased as soon as the DH is computed.

```text
seed = HKDF("", DH, "Vauchi_Notice_Handshake_v7|" ‖ label, 32)
root_0 ‖ notice_0 ‖ record_0 ‖ control_0 ‖ opening_0 ‖ proof_0
     = HKDF("", seed, "Vauchi_Notice_Seed_v7|" ‖ label, 192)
```

Each output is 32 bytes. `seed` is erased once they exist. The seed
epoch's ID is `HKDF(root_0, "", "Vauchi_Notice_Epoch_v7", 16)`, as for
every epoch below. The seed epoch has number 0 and is, for every rule,
an epoch S opened and R derived and named.

**An epoch** opened on refresh number `n (4)` and key `R_n` (private
key `r_n`), from base epoch `b`, with ephemeral private key `e` and
public `E`:

```text
secret   = DH(e, R_n) ‖ DH(S device private, R_n)               (S)
         = DH(r_n, E) ‖ DH(r_n, S device public)                (R)
ctx      = label ‖ n ‖ E ‖ R_n ‖ epoch ID of b
conf     = HKDF(root_b, secret, "Vauchi_Notice_Confirm_v7|" ‖ ctx, 16)
root ‖ notice ‖ record ‖ control ‖ opening
         = HKDF(root_b, secret, "Vauchi_Notice_Root_v7|" ‖ ctx, 160)
proof    = HKDF(root, DH(e, R device public),
                "Vauchi_Notice_Proof_v7|" ‖ ctx, 32)            (S)
         = HKDF(root, DH(R device private, E), same info, 32)   (R)
epoch ID = HKDF(root, "", "Vauchi_Notice_Epoch_v7", 16)
key ID   = H(R_n)[:8]
```

Everything an opening rests on goes into `ctx`, and so into what it
derives. Two epochs opened under one number have different IDs. If any
of the three DH results (the two in `secret` and the one in `proof`) is
invalid, the opening is not made (S) or is treated as one whose
confirmation failed (R). `secret` and `e` are erased once the outputs
exist. `record` is reserved for the encrypted headers of ordinary
records (ADR-081). The epoch's number is `n`.

**The notice chain** carries update keys from S to R. From chain key
`ck_i` at position `i`, positions starting at 0:

```text
tag_i (16) ‖ mk_i (32) ‖ ck_{i+1} (32)
    = HKDF("", ck_i, "Vauchi_Notice_Chain_v7", 80)
```

A step gives a 16-byte tag, a single-use message key and the next chain
key; the old chain key is deleted. `ck_0` is the epoch's `notice`;
whoever builds the chain's writer or reader takes it out of the epoch's
keys, which keep no copy: a copy kept there would read the whole chain
again. S holds only its next `ck`. R holds `ck` of its lowest position
not yet stepped past and a cache of tags for the window of section 6.

**Control records have addresses, not positions.** Refreshes and
openings do not travel on a chain. No counter that only the writer
advances is involved, so no loss, delay or forged record can move a
reader's view away from the honest writer's.

```text
refresh address:  tag (16) ‖ mk (32)
    = HKDF(control_b, "", "Vauchi_Notice_Refresh_v7|" ‖ wk ‖ j, 48)
opening address:  tag (16) ‖ mk (32)
    = HKDF(opening_b, "", "Vauchi_Notice_Open_v7|" ‖ n ‖ j, 48)
```

`b` is the epoch the record is sealed in, `wk (4)` the writer's week
when it assigns the address, `n (4)` the number of the refresh the
opening answers, and `j (1)` an attempt from 0 to 3. A writer uses an
address once: the next `j` of each epoch and week, and of each base and
number, is saved state of its own, kept as long as the epoch, and is not
reset when a refresh is replaced or the clock revisits a week (section
8). Two keys under one refresh number share that number's four opening
addresses in a base: once a copy's key has used them, R's own key is
opened only on its next refresh. These keys do not step and are kept as
long as the epoch's `control` or `opening` key is.

## 3. The seal and the notice

```text
mac key ‖ enc key = HKDF("", mk, "Vauchi_Notice_Seal_v7|siv", 64)
iv      = HMAC(mac key, len(aad) (4) ‖ aad ‖ plaintext)[:16]
sealed  = iv ‖ (plaintext XOR XChaCha20(enc key, nonce = iv ‖ 0^8,
                                        counter = 0))
notice  = tag (16) ‖ sealed (80)                    96 bytes, aad = tag
```

Opening recomputes `iv` and compares in constant time. The plaintext is
64 bytes:

| Kind | Byte 0 | Bytes 1–32 | Bytes 33–63 |
|---|---|---|---|
| Update key | `0x00` | update key | commitment (31) |
| Refresh | `0x01` | `R_m` | `m` (4) ‖ proof tag (16) ‖ `0^11` |
| Opening | `0x02` | `E` | `n` (4) ‖ key ID (8) ‖ `conf` (16) ‖ `0^3` |

An update key travels at a notice-chain position, a refresh at a
refresh address, an opening at an opening address.

`proof tag = HMAC(proof key of the sealing epoch, "refresh" ‖ m ‖ R_m ‖
epoch ID of the named epoch)[:16]`. The name is not sent. Refresh
numbers start at 1; a direction whose next number would be 2^32 is
closed and started anew (B6).

## 4. Content

A card update's body is the card as one of S's groups sees it,
serialised by Core, with inside it an opaque 16-byte group ID, a
32-bit version and the sender's identity signature. It is whole, not a
difference from an earlier card, so a receiver may skip edits. One
update key belongs to one group and one version. A contact is in at
most 32 groups; S refuses a 33rd. When the contact leaves a group, S
erases that group's latest key from the direction and no later view
carries it. A body is at most 3,984 bytes, 8 records. Larger bodies
(avatars) are not defined here (section 9).

```text
payload     = h_1 ‖ … ‖ h_(count−1) ‖ body, zero-padded to 512 × count
chunk_i     = payload[512 i .. 512 (i + 1)]
h_i         = SHA-256("Vauchi_Update_Chunk_v5" ‖ i (2) ‖ chunk_i)[:16]
record key  = HKDF("", update key, "Vauchi_Update_Record_v5", 32)
commit key  = HKDF("", update key, "Vauchi_Update_Record_v5|commit", 32)
commitment  = HMAC(commit key, count (2) ‖ length (4) ‖ chunk_0)[:31]
ID          = HKDF("", update key,
                   "Vauchi_Update_Record_v5|id" ‖ w ‖ i ‖ t, 16)
record      = ID (16) ‖ nonce (24) ‖
              AEAD(record key, nonce, aad = ID,
                   i (2) ‖ count (2) ‖ length (4) ‖ chunk_i (512))
              ‖ tag (16)                                     576 bytes
```

`AEAD` is XChaCha20-Poly1305 with a random nonce, the initial counter
as the construction defines it. `i` runs from 0 to `count − 1`;
`count` is 1 to 8, the fewest records whose 512 bytes each hold the
body and `count − 1` hashes; `length` is the body's length; the
payload's unused bytes are zero. In the ID, `i` is 2 bytes. Record 0
carries the hash of every later chunk, and the notice's commitment
binds record 0, so each record is checked on its own: a group member,
who holds the update key too, cannot make a forged record stand in for
an honest one.

`w (4)` is the publication's week and `t (1)` the transmission, 0 to 3:
each time S writes record `i` of a publication it uses the next `t` for
that record, so no ID is ever written twice and the gateway cannot
link a resend to the first write. After four transmissions of a record
in one publication S stops; the next publication carries it.

**A publication** is all records of a group's current body under one
`w`, fixed when its first record is assigned: S's week then. While that
week is not later than the `w` of the last publication under the same
update key, the publication waits for a later week. A publication
more than a week behind S's week writes what it still has under S's
week, which R still looks in. So a `w` is never used twice for a key,
and no publication takes a week ahead of S's clock when it is
assigned, whatever the clock does (one under way keeps its week
through a later set-back, which the three-day bound keeps in R's
window): a weekly publication brought forward by a clock set back and
corrected waits, instead of taking a week R does not look in yet. A
publication is completed when each of its records was written in an
acknowledged session or has used four transmissions.

**Publishing (S5).** S queues a publication of a group when the group is
edited, when a contact device joins a group that has no publication yet,
and again when the group's last publication was completed a period ago;
one publication a group is queued at a time. When an edit supersedes a
body, every queued record and view of the old one is removed and the old
update key erased. A session writes an update notice for a new edit only
once record 0 of that edit's publication is written, in that session
or an earlier one; content is chosen first. Content slots go to the
publication waiting longest, a new edit first among those waiting as
long (section 8). When the slots of a week do not hold every group's
weekly publication, a group's turn comes later; nothing else changes.

**Reading.** Per direction R keeps pending entries and installed
commitments.

- On reading an update-key notice: if its commitment is among the 32
  installed most recently, drop the notice. If its update key is
  already pending, set the entry's time to now and keep its chunks: a
  publication may outlast 21 days, and each view renews the entry.
  Otherwise add a pending entry `(update key, commitment, time)`; at
  most 32 a direction, the one with the oldest time dropped. Notices in
  one session take the order the batch gives, which the gateway
  chooses: it can make a 33rd key push out the latest one for a view's
  time, but only with 32 distinct keys S really wrote. A contact is in
  at most 32 of a user's groups, so a view alone never holds more keys
  than the 32.
- In each session, for every pending entry, R wants these IDs among the
  content slots of the batches it downloaded in this session: every
  `w` in `week(now) − 2 … week(now) + 1`, every `t` in 0…3, and every
  `i` it does not hold, below `count` once a record told it, else in
  0…7. A chunk is the same in every publication of one key, so chunks
  from different publications complete one body.
- A slot with a wanted ID is opened with the record key, record 0
  first in a session. Ignore the slot when opening fails; when `i` is
  not the index the ID was wanted for, or `count` or `length` is out of
  range. Record 0 is kept only if the commitment over it matches the
  notice's; a later chunk only once record 0 is held, with the same
  `count` and `length`, and if its hash matches the one record 0
  carries for it. Anything else is ignored and changes nothing.
- When all `count` chunks are held: join them and take the body after
  the hashes, cut to `length`, and check the signature under the
  sender's identity key. It passes: hand the body to Core, add the
  commitment to the installed list, erase the entry, its update key and
  its chunks. It fails: erase the entry, its key and its chunks.
- An entry whose time is 21 days old is erased with its key and
  chunks: a week longer than the longest absence section A allows, so a
  view arriving after a 14-day absence still renews it. A superseded
  key is not sent again, so it goes 21 days after its last notice.

Core keeps, per sender and group ID, the body with the highest
version; how it shows several group bodies as one card, and what it
does with two different bodies of one version, are Core's.

## 5. What each device stores

Per direction, in saved state. "Three periods" is abbreviated 3P. Each
item names what is kept and, after the colon, until when.

Receiver R:

- The current epoch (number, root, epoch ID, control, opening and proof
  keys, notice-chain reading state): until replaced by a move.
- An epoch it left (epoch ID, root, control, opening and proof keys):
  3P after R left it or last sealed a refresh in it, the later.
- Per epoch kept and week, the next refresh attempt `j`: with the
  epoch.
- The same epoch's notice-chain reading state and skipped keys: 3P
  after leaving.
- Each refresh issued (number, key ID, time): 3P after issue.
- The private keys of its newest three refreshes not yet used: until
  used, displaced by a newer refresh, or 3P after issue with their
  issued entry.
- Each number used, the `H(E)` of the opening accepted: 3P after issue.
- Its newest refresh (number, key, the epoch named, the time it was
  made): until replaced.
- The epoch of the most recent alarming record: 3P after that alarm.
- Per opening address read, `H(record)`: while the address is watched
  (section 6).
- Pending entries and installed commitments: section 4.

Sender S:

- The epoch it writes in: until replaced by following.
- The times of the notice positions assigned in this direction: each
  for one period, whatever S follows.
- An epoch it opened (number, root, epoch ID, control, opening and
  proof keys, notice-chain writing state, whether and when last named):
  section 7, step 3.
- The epoch IDs of epochs it erased: the newest 64.
- Refreshes read (number, key, epoch ID named or "none", whether
  opened, time): 20 weeks, as long as their addresses are watched; at
  most 64, the oldest by time dropped.
- The one opening not yet named (every field of the record, and the
  next attempt `j`): until named, four attempts made, its epoch erased,
  or replaced (section 8).
- Whose control turn is next, the opening's or the views': always
  (section 8).
- Per refresh address read, `H(record)`: while the address is watched
  (section 6).
- Each group's latest update key, body, the `w` of its last
  publication, per record the next `t`, and the time that publication
  was completed: until superseded.

## 6. Reading a slot

**What a device watches.** Tags are cached and recomputed when the set
changes.

- R, notice chains: for its current epoch and each epoch it left within
  3P, the 512 positions from the lowest not yet stepped past, and the
  skipped positions it keeps.
- R, opening addresses: for each epoch it sealed a refresh in within
  3P, each number it issued within 3P and the two numbers above its
  newest, attempts 0 to 3.
- S, refresh addresses: for each epoch it keeps, each week from
  `week(now) − 18` to `week(now) + 1`, attempts 0 to 3. Eighteen weeks
  cover the relays' 120 days.

For every notice slot of a downloaded batch:

1. **Recognise.** Look the slot's first 16 bytes up among the watched
   tags. No match: not for this device.
2. **Open** the seal with the message key the tag belongs to. Failure:
   ignore the slot; nothing changes and nothing is raised. The position
   stays unread and its key in place. Bytes the gateway alters or
   injects therefore do nothing.
3. **A notice-chain position** `p`. Positions below `p` not yet read
   become skipped: each keeps its message key, stamped with the time it
   was skipped; if more than 256 are skipped on the chain, the lowest
   are erased. Step the chain past `p`; erase the message key once the
   record is dispatched. A position read is not recognised again, so a
   replay does nothing. A skipped position read later is removed from
   the skipped set and changes nothing else.
4. **An address.** Compare `H(record)`, the whole digest, with what is
   kept for the address, and with any record read at the same address
   earlier in this session. Nothing kept: keep it, and dispatch. Equal:
   drop the record. Different: raise the alarm, and dispatch. A key
   holder chooses both records, so a shorter hash would let it find two
   that compare equal.
5. **Dispatch** on the kind byte. A kind unknown or not listed for
   where the record travelled, or nonzero bytes where zero is required:
   ignore the record; its position counts as read.

A skipped key is erased 3P after its stamp. Only a device holding the
epoch's keys can put two different records that open at one address,
so step 4's alarm is never raised by honest use or the gateway.

## 7. A session

A session is one background wake-up or one open-app tick. Steps 1 to 5
work in memory. Step 6 saves once and then writes. A crash before the
save leaves the previous session's state, and the batches are read
again; reading again changes nothing that reading once did not, apart
from raising again an alarm already raised.

1. **Read.** Download every batch since the last saved session, in
   order; read every notice slot (section 6); keep all slots for this
   session. Whenever step 3 moves R to a new epoch, R reads the
   session's notice slots again for that epoch's chain before step 2
   is done, so notices S wrote there in the same batches are not
   missed. Openings are not looked for again: the new epoch's opening
   addresses carry nothing yet.
2. **Updates (R)**, after step 3. Handle the update keys read, then try
   every pending entry against this session's content slots
   (section 4).
3. **Openings (R)**, in rising order of number, ties by attempt; then
   **refreshes (S)**, in rising order of number, ties by reading
   order.
   - **Opening** on number `n`, read at an address of base `b`.
     1. The record's `n` is not the address's: ignore the record. `n`
        is above R's newest number, or the record's key ID is not the
        one issued under `n`: alarm; stop.
     2. `H(E)` equals the one accepted under `n`: stop. Another was
        accepted: alarm; stop.
     3. `n` is not above the current epoch's number, or R no longer
        holds the private key: stop.
     4. Derive with base `b`. `conf` differs: alarm; stop.
     5. Record `H(E)` under `n`, erase the private key, and move: the
        new epoch becomes current and the old one is left.
   - **Refresh** with number `m`, read in epoch `x`.
     1. Find the name: the ID, among the epochs S keeps and then those
        it erased, that verifies the proof tag; else "none". A refresh
        S already read, with this key and this name, is dropped at no
        cost wherever it was sealed. Of the others, a session handles
        the eight with the highest numbers, ties in the order read;
        the rest stay unread, with no hash kept, so a later delivery is
        read. Copies of one refresh at different addresses, all new to
        the session, count once each against the eight. Two different
        records at one address in the session still raise step 4's
        alarm, whether or not either is handled.
     2. Look `(m, R_m, named ID)` up in the refreshes read. Present:
        stop. Another key or named ID present under `m`: alarm, and go
        on.
     3. Add it. **Follow:** the ID of a kept epoch: S writes in it from
        now on, marks it named now, and queues a current view
        (section 8). The ID of an erased epoch: S changes nothing.
        "none": alarm; S writes in `x` from now on and queues a
        current view.
     4. **Open**, unless `(m, R_m)` is marked opened, the four
        addresses of `m` in base `x` are spent, or the queued opening
        has a higher number than `m` (section 8): make `e`, derive
        with base `x`, keep the epoch as unnamed with the time, mark
        opened, and queue the opening in place of any queued one. A
        queued opening with a lower number than `m` leaves the queue
        first, whether or not `m` opens. If the DH result is invalid,
        mark opened and do nothing more. "Marked opened" means
        handled: a refresh that opened nothing under this rule is not
        opened later.
   - **Epochs S keeps** after this step: the one it writes in; and
     every epoch whose number is not below the highest number S has
     followed a name to, named or not, whatever its age. Below that
     number: a named epoch for 3P from its last naming, an unnamed one
     for 3P from its opening. At most 24 named and 12 unnamed, erased
     named longest ago first and lowest number first, never the two
     kinds just said to be kept. R only moves upwards and seals every
     refresh in its current epoch, so without a writing copy S always
     keeps an epoch R seals in, also after an older refresh delivered
     late made it write elsewhere. One exception to the first rule:
     once S has opened an epoch on a refresh numbered `m` (an invalid
     DH result opens none), it erases every epoch still unnamed whose
     number is `m − 3` or lower, except the one it writes in. R can
     never move into such an epoch: R had either moved past it when it
     made `m`, or held the newer unused keys `m − 2` to `m`, which
     displace the key of `m − 3` (R keeps three). So S keeps at most
     three unnamed epochs that R can still use. A copy of R can seal
     such a refresh and make S erase too early; that is a copy that
     writes (section F). Whatever the rule, an epoch that is the base
     of an opening still queued is kept until that opening leaves the
     queue (four attempts, or its epoch named): R may seal refreshes in
     an epoch it can no longer move into, the one it left most
     recently, and the answer to such a refresh is sealed there. S
     applies these rules until none erases anything more: an opening
     whose own epoch is erased leaves the queue, and its base is then no
     longer kept for it, in the same step. An epoch erased leaves its
     ID.
4. **Refresh (R, rule R1).** If no refresh was ever made, or seven days
   have passed since the newest was made: make `R_m` with the next
   number and replace the queued refresh. A queued refresh is sealed,
   each session until acknowledged, in the current epoch, in the epoch
   left most recently if R still keeps its keys, and in the epoch of the
   most recent alarming record if R still keeps it and it is neither of
   those. Every copy carries the name fixed when the refresh was made:
   R's current epoch at that moment.
5. **Edits (S).** For each group edited since the last session: a new
   update key and body, the old ones removed (section 4); queue its
   publication and, for each contact device in the group, an update
   notice. Queue the weekly publication of each group whose last one
   is a period old.
6. **Assign, save, write** (section 8).

## 8. Slots, dummies and queues

From ADR-081, restated because P6 rests on it:

- A background session writes exactly 80 notice slots and 5 content
  slots; an open-app tick exactly 40 and 2. The counts are public and
  the same for every device, whatever it has to send.
- An unused slot holds a dummy: uniformly random bytes of the slot's
  size. The slots of a session are written in an order drawn at random.
- In the alpha and beta every device writes in the one cohort and reads
  all of it, so a write names no recipient. Routing between cohorts is
  release work (ADR-081) and outside this chapter.

Queues, in saved state, shared by all of a device's directions. An
entry holds what the record says, never sealed bytes.

- **Updates:** one entry a contact device and group, the latest.
- **Control:** per direction at most one refresh (R), the openings not
  yet named with attempts left (S), and one current view (S): an
  update-key notice for each group the contact is in, with the group's
  latest key.
  - A group whose update is queued has its view in that entry: one
    notice carries both, so a session never writes one key twice.
    Within a direction, updates and views go in one queue, the group
    whose notice was last written longest ago first, acknowledged or
    not; each still needs a slot of its kind. So neither the 128
    positions a period, a group edited at the full rate, nor withheld
    acknowledgements can leave one group out for good.
  - A direction holds at most one opening. A refresh with a higher
    number than the queued opening's removes it, and queues its own if
    it opens an epoch; one with a lower number opens nothing while that
    opening is queued; under one number the key read last replaces the
    one before (S4). Once the opening leaves the queue, named, spent or
    erased, the next refresh read opens again: a highest number kept
    for good would let one forged refresh stop every later opening.
  - The direction's control turns alternate between its opening and
    its views: a session with one control slot for the direction writes
    the kind that did not go last, and one with two or more writes the
    opening and then views. A view still needs a position; when none
    can take one, the slot goes to the opening. Only the views the
    positions left in the period can take are counted, in the one queue
    of updates and views.
  - A new edit's update is eligible once record 0 of its own
    publication is written, not the group's earlier one. Content slots
    go to the publication waiting longest, a new edit first among those
    waiting as long. So a budget that stays full delays but never
    starves a record.
  - Directions take turns, the one served longest ago first, each queue
    by its own turn: a direction's update queue and its control queue
    each remember when they last wrote, so an update is no turn of the
    control queue. Every time these orders use is pulled back to the
    clock as in section 1. The turn times are kept by the direction's
    place in the list a session is given; adding a contact moves the
    receivers' places and misorders their turns until each has written
    again; this is read from the code, not tested.
- **Content:** publications, in the order of section 4.

**Assign.** The session chooses what fits: each notice slot from the
update queue, except that the 8th, 16th and every further 8th takes
from the control queue when it is not empty; when the update queue is
empty the control queue fills the rest. For each chosen record the
device assigns where it will travel and advances that counter:

- an update-key notice or a view's notice: S's next notice-chain
  position in the epoch it writes in. S derives the tag and message
  key and steps the chain. If 128 positions were assigned in this
  direction within the last period, the record is not chosen and stays
  queued;
- a refresh copy: in each epoch it is sealed in, the next attempt `j`
  of the current week. With no attempt left in that epoch and week, no
  copy is sealed there until the next week;
- an opening: the next attempt `j` under its number in its base, one
  attempt a session. A second key under a number replaces the first and
  gets the attempts left. After the fourth, the opening leaves the
  queue; the epoch stays as S keeps unnamed epochs. An opening whose
  base epoch S has erased leaves the queue too;
- a content record: the next `t` of that record in its publication,
  the records with the fewest transmissions first, lowest index among
  equals, so that with too few slots every record goes once before any
  goes again.

**Save** the state with every counter advanced, in one transaction.
Tags and message keys of the assigned records are held in memory only.

**Write.** Seal each record and write the session. When the relay
acknowledges it, remove the written entries from their queues at the
next save: an update notice, a view and a content record leave; a
refresh leaves once every epoch it is sealed in holds a copy written
in an acknowledged session, including an epoch whose addresses of the
week were spent, which gets its copy in a later week; an opening stays
until named or four attempts. A session not acknowledged, or a crash
after the save, leaves the entries queued: the next session assigns
them new positions, addresses and transmissions. A position or address
assigned and never written is simply never read.

Nothing here depends on how often sessions happen: however many are
unacknowledged, a notice chain advances at most 128 positions a period,
a quarter of the reader's window, a refresh uses at most four addresses
an epoch and week, an opening four, and a content record four a
publication.

## 9. Not here

- Bodies above 3,984 bytes. An avatar (ADR-042: at most 32 KB) needs
  up to 63 records and many sessions; its publication, and how long R
  may hold its key while it arrives, are designed with the avatar
  work.
- The serialisation of the card body, group IDs, and what a version
  does at the top of its range, are Core's.
- The seed handshake's message format inside the Core session.
- A device restored from an image that holds notice state (B5 excludes
  that state from backups).
- Quota enforcement at the relay, witnessed batch roots, chunked
  download and when a session counts as acknowledged are ADR-081's and
  the relay's.
- P6 is argued for a gateway that watches, delays, drops and replays;
  it is not analysed against one that adapts its tampering to what it
  observes.

## Vectors

Known-answer values for sections 2 to 4, and conformance schedules for
one direction, are in [Test Vectors](../vectors.md#notice-core-proposed).
