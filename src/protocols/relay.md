<!-- SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- description: The Vauchi relay: a store-and-forward service under rotating mailbox tokens, behind an OHTTP hop, so neither hop sees both a user's address and their content. -->

# Relay

> **Status: checked 2026-10-30** against `vauchi/relay` `f3034bb`,
> `vauchi/ohttp-relay` `a4e7c6e` and `vauchi/core` `a9a911b0a`. The
> two hops between a client and its mail: the **application relay**
> (the gateway, which stores blobs) and the **outer relay** (which
> forwards encapsulated requests and sees the client's address). Claims
> backed: [S3](../claims.md), [S4](../claims.md).

## Goal

A store-and-forward service that lets contacts who are never online
at the same time exchange updates, and that learns as little as a
service can: no plaintext, no identity, no address together with
content. The application relay sees content-shaped bytes under
rotating mailbox tokens; the outer relay sees addresses and opaque
encapsulated bytes; neither sees both.

## Actors

- **Client**: `vauchi-core` on a user's device.
- **Outer relay** (`vauchi-ohttp-relay`): a pass-through proxy that
  forwards OHTTP requests to the gateway. It binds plain TCP; the
  client's TLS connection ends at the deployment's proxy in front of
  it.
- **Application relay** (`vauchi-relay`): the OHTTP gateway and the
  blob store, with the escrow, exchange broker, recovery and guardian
  stores the other chapters use.
- **Operator(s)**: in the alpha one operator runs both hops on two
  hosts (ADR-037 addendum 2026-09-08).
- **Attacker**: a compromised hop, an observer of either hop's
  network, or an anonymous client flooding mailboxes.

---

## Message flow

```text
Client                      Outer relay                     Application relay (gateway)
  | GET /v2/ohttp-key-signed  |--> forwards, caches 300 s     |  signed window key record
  | verify anchor → intermediate → (window, KeyConfig)        |
  | POST /v2/ohttp            |                               |
  |   HPKE(KeyConfig, pad(inner JSON { version: 2, action, ...payload }))
  |-------------------------->|--> POST /v2/ohttp (no client headers, no IP)
  |                           |                               | decapsulate, unpad,
  |                           |                               | dispatch action,
  |                           |                               | pad reply to a ladder rung,
  |                           |<-- message/ohttp-res ---------| encapsulate
  |<--------------------------|                               |
  | or: POST /v2/ohttp-async {ticket}; GET /v2/ohttp-async/:ticket later
```

Every action a client takes against the gateway (send, fetch, ack,
register, purge, exchange, escrow, recovery, guardian, content) rides
inside the encapsulated inner request; the gateway serves the same
actions on plain `/v2/*` routes only for operators and tests, and a
client in production refuses to use them (B6).

---

## A. The application relay

### Normative operations

Source: `relay/src/http_api.rs`, `storage.rs`, `config.rs`,
`rate_limit.rs`, `padding.rs`, `handler/verify.rs`,
`vauchi-protocol/src/v2.rs`.

**A1. Routes.** `POST /v2/send`, `/v2/fetch`, `/v2/ack`,
`/v2/register`, `/v2/purge`, `/v2/exchange/{offer,claim,complete}`,
`/v2/recovery/{store,query}`, `/v2/guardian/{store,query,delete}`,
`POST /v2/ohttp`, `GET /v2/ohttp-key-signed`,
`GET /v2/ohttp-anchor-rollover`, `GET /v2/health`, on the main
listener together with `/metrics`, `/health`, `/build-info` and `/`
(`http.rs`). When `RELAY_OHTTP_GATEWAY_ADDR` is set, a second
listener serves only `/v2/ohttp`, `/v2/ohttp-key-signed` and
`/v2/ohttp-anchor-rollover` (`create_gateway_router`), the one an
outer relay on another host reaches. With federation on, a mutual-TLS
listener serves `GET /v2/federation/health` and
`POST /v2/federation/message` (A10). Every `/v2` body is at most
128 KiB (`DefaultBodyLimit`): malformed JSON is `400`, a wrong content
type `415` and a body over the limit `413`. A request MAY carry
`X-App-Compat-Version`; a missing or unparsable header counts as
version 0. The relay answers `426 upgrade_required` below its minimum
version once the grace period is over, adds `X-Min-Version` and
`X-Warn-Version` to every response it lets through, and adds
`X-Upgrade-Deadline` only during the grace period
(`version_policy.rs`, 14 days by default). Over OHTTP the outer relay
forwards no client header, so the gateway always sees version 0: a
minimum above 0 refuses every encapsulated request once its grace
period ends (vauchi/private#945).

**A2. Send** (`handle_send_logic`). Body `{ recipient_id, ciphertext,
origin_hint? }`. The relay MUST refuse when the per-mailbox rate
limit for `recipient_id` is exhausted (`429`, `Retry-After`), when
`recipient_id` is not 64 hex characters, when `ciphertext` is not
base64, or when the mailbox would exceed its quota: by default 1 000
blobs or 50 MB per recipient token (`429 quota exceeded`; zero means
unlimited). The relay validates `recipient_id` before it spends a
rate-limit token and lower-cases it, as it lower-cases the ids of
`ack` and `fetch`, so `AB…` and `ab…` are one mailbox with one
rate-limit key (`a_send_to_an_upper_case_token_lands_in_the_lower_case_mailbox`,
`an_invalid_recipient_id_spends_no_rate_limit_token`; before
vauchi/private#944 they were two, and the token was spent first). It
stores `(uuid, recipient_id, bytes, created_at, hop_count = 0,
origin_hint)` and answers
`{ status: "ok", blob_id }`. The relay does not check the
ciphertext's shape; what it stores is whatever the client sent, and
the sender's address is not part of the record. The rate limiter is a
token bucket per key, 60 per minute by default, tracking at most
100 000 keys: when all are in use and none has refilled completely, a
new key is refused rather than an old bucket evicted.
Before storing, the relay also requires the exact serialized
single-blob fetch response plus its four-byte padding prefix to fit
the 96 KiB fetch bucket; JSON escaping of `origin_hint` counts toward
this limit. A body that fits send can still be refused at this check.

**A3. Fetch** (`handle_fetch_logic`). Body `{ mailbox_tokens: [1 to
100 tokens] }`. The relay returns, oldest first, every stored blob
whose `recipient_id` is one of the tokens and whose age is below the
TTL, as `{ blob_id, ciphertext, created_at, mailbox_token,
origin_hint }`. Pagination measures the exact serialized JSON page
plus its four-byte padding prefix against 96 KiB; `truncated: true`
means another deliverable blob remains after the client acknowledges.
Legacy rows too large for a fetch are retained and skipped rather than
blocking healthy rows. An additive `undeliverable` object reports their
`count`, `details_truncated` and at most two entries containing
`blob_id`, `mailbox_token` and `reason: "exceeds_fetch_delivery_limit"`.
Diagnostics are deferred if a full healthy page leaves no room. They
alone do not set `truncated`, and fetch never silently deletes them. Fetching does not remove anything (`peek_many`); an
expired blob is never served even before the hourly sweep removes it
(`fetch_enforces_retention_before_cleanup_over_http_and_ohttp`). The
rate limit key is the first token. Nothing authenticates a fetch: the
token is the capability.

**A4. Ack** (`handle_ack_logic`). Body `{ recipient_id, blob_id }`.
Deletes that one blob from that mailbox and answers whether it existed.
A duplicate acknowledgement is harmless. There is no signature or
sender authentication: possession of the mailbox token and blob id is
a destructive bearer capability. Fetch discloses both, so anyone who
can fetch a mailbox can also acknowledge its blobs without decrypting
them. A sender knows the destination token and may obtain blob ids by
fetching it; knowledge of a token is not exclusive to the recipient.

**A5. Register** (`handle_register_logic`). Body `{ mailbox_tokens }`,
at most 1 900 tokens of 64 hex characters each. Under the HTTP
transport the relay validates and acknowledges and keeps nothing: the
fetch carries its own token list (ADR-029 addendum 2026-05-22). The
client still pads its list to a multiple of 256 and shuffles it.

**A6. Retention.** A blob lives `blob_ttl_secs`, 120 days by default,
from its `created_at`; the sweep runs hourly; a blob offloaded to a
peer keeps its original age. Tests:
`retention_keeps_day_100_data_across_restart_and_ack_removes_only_that_blob`,
`retention_expires_at_the_exact_boundary_and_preserves_a_later_envelope`.

**A7. Purge** (`handle_purge_logic`). Body `{ public_key,
purge_token(32), signature, timestamp, erase_guardian_set }`. The
relay MUST verify the Ed25519 signature by `public_key` over
`public_key || purge_token || timestamp_be [|| "erase-guardian-set"]`
(`verify_purge_ed25519`), refuse a timestamp more than 60 s from its
clock and a replayed nonce, and only then delete every blob and
forwarding hint stored under `hex(public_key)`, the recovery proofs
owned by that key and, when asked, the guardian set keyed by
`SHA-256(public_key || "guardians")`. The body names no mailbox: every
effect of a purge is bound to the verified key, and an old client's
`recipient_id` is read past
(`a_purge_empties_the_signing_keys_mailbox_and_not_the_one_its_body_names`).
Before vauchi/private#944 the body's `recipient_id` chose the mailbox,
so any key pair could empty any mailbox whose token it held. Every
signature the relay checks, here and in Social Recovery A4 and B3,
goes through dalek `verify_strict`, as Core's do: aws-lc's verifier
accepted the identity point as a key with `S = 0` for any message
(`test_verify_purge_ed25519_rejects_the_identity_point_as_a_key` and
its guardian and recovery-owner twins; vauchi/private#944). Purge
sends the identity key itself, by design: deletion is the identity's
own signed act (the recovery store's `owner_pk` and the guardian
store's `designator_pk` carry one too, see the routes below) (Keys and Cards, C3; the
hard-shred lane `hard_shred_after_grace_fanout_over_outer_hop_only`).

**A8. Response padding** (`padding.rs`). Every OHTTP reply is padded
before encapsulation: a fetch to the smallest rung of 4 KiB, 32 KiB or
96 KiB that holds it (`ohttp_fetch_size_ladder_tests.rs`), content
files to 64 KiB, 512 KiB or 2 MiB (16 or 96 KiB compressed), every
other action to the 256/512/1024/4096-byte buckets of the client's
padding. Above the top rung of each ladder a reply pads to a multiple
of 256 bytes. The inner request is unpadded by its length prefix
only: the relay does not check that its padded length is a bucket
(`is_valid_bucket_size` is called only in `federation_protocol.rs`).

**A9. Jitter.** `delivery_jitter_min_ms`/`max_ms` (50 to 500 ms) are
configured and tested in `jitter.rs`, but no request path calls
`generate_jitter`: on the HTTP transport a blob is served as soon as
it is stored.

**A10. Federation** (`federation_core.rs`, `federation_http.rs`,
ADR-052). Above 80 % of its storage a relay offloads its oldest
unforwarded blobs to the first configured peer
(`config.federation.peers.first()`) over mutual TLS (`POST
/v2/federation/message`, blob bytes raw, integrity `SHA-256` over
the padded ciphertext), keeps a forwarding hint `routing_id → peer`
and deletes the blob once the peer accepted; a peer refuses above
95 % and refuses a blob that already hopped once. Federation is off
by default; the peer registry is never filled on the shipped relay
(vauchi/private#872), and Core cannot follow a forwarding hint
(vauchi/private#835), so an offloaded blob is unreachable to its
recipient.

**A11. Mailbox cohorts (proposed, off by default)** (`cohort.rs`,
`cohort_api.rs`; ADR-081, the [Notice Core](./notice-core.md)). The
relay answers four actions only inside an OHTTP request, and only when
`RELAY_COHORT_STORE` names a store (`memory` or a SQLite file); unset or
empty, every cohort action answers `not_enabled`. No deployment sets it.

- `cohort_register {cohort, device}`: adds a 32-byte device key to a
  cohort of at most 330 devices (`cohort_full` past that).
- `cohort_write {cohort, device, tier, class, slot, record}`: stores one
  record in the current period of a tier (`fast`, 60 seconds;
  `background`, 4 hours) at a numbered slot of its class (`notice`,
  96 bytes, slots below 40 fast and 80 background; `content`, 576
  bytes, below 2 and 5). The device must be in the cohort
  (`not_in_cohort`), the record the class's size (`wrong_size`), the
  slot in range (`no_such_slot`). The same bytes again answer `again`;
  a slot may be replaced once (`replaced`), then `slot_used`.
- `cohort_batch {cohort, tier, class, at}`: once the period holding
  `at` has ended (`not_published` before), its record count, period
  and number of chunks; `expired` 120 days after it ended.
- `cohort_chunk {cohort, tier, class, period, index}`: chunk `index` of
  that batch, 64,512 bytes of whole records in the order of their
  bytes, the last zero-padded (`no_such_chunk` past the end). The order
  says nothing of which device wrote a record or when.

Every member downloads every chunk of its cohort's batch, so the relay
does not learn which records a device reads. It does learn which
devices registered in a cohort and when each wrote; see the Notice
Core's claims.

### What the relay records

Prometheus counters and gauges (`metrics.rs`): blobs created,
delivered, expired and stored, messages received, sent and rejected,
rate-limited requests, request duration, connections, federation
counters, recovery proofs active, the intermediate certificate's
expiry. No token, address or payload appears in a metric or a log
line; the RG-6 lane
`integration_ohttp_relay_observations_exclude_update_content` reads
the process output and `/metrics` for a routed update's payload and
token and fails if either shows.

---

## B. Oblivious HTTP

### Normative operations

Source: `relay/src/ohttp_gateway.rs`, `ohttp_signer.rs`,
`ohttp_window_keys.rs`, `ohttp_rollover.rs`;
`vauchi-protocol/src/ohttp_key.rs`; `ohttp-relay/src/*`;
`vauchi-core/src/network/ohttp_client.rs`,
`crypto/ohttp_key_trust.rs`, `api/vauchi/sync_http.rs`,
`network/http_transport/delayed.rs`.

**B1. Encapsulation.** RFC 9458 with the `ohttp` crate: the client
encapsulates `pad(JSON { version: 2, action, ...payload })` to the
gateway's KeyConfig with a fresh client context per request and posts
`message/ohttp-req` to the outer relay's `/v2/ohttp`; the gateway
decapsulates, requires `version == 2`, dispatches the action, pads
the JSON reply (A8) and encapsulates it as `message/ohttp-res`. Only
the client can open the reply.

**B2. Window keys.** The gateway serves one HPKE key per 24-hour UTC
window, `window = floor(unix / 86 400)`, key id `window mod 256`,
each window's key from its own random seed; it keeps the previous,
current and next window across restarts (`VOW1` file). A stolen seed
file opens at most three windows.

**B3. Signed key record** (`/v2/ohttp-key-signed`,
`SignedKeyConfig`). The record a client fetches is

```text
version 0x01 || window(8) || key_config_len(2) || key_config
|| sig_intermediate(64) over
     ("vauchi-ohttp-keyconfig-v1" || window_be || key_config)
|| intermediate_pk(32) || not_before(8) || not_after(8)
|| sig_anchor(64) over
     ("vauchi-ohttp-intermediate-v1" || intermediate_pk
      || not_before_be || not_after_be)
```

An offline Ed25519 anchor certifies the intermediate for 90 days
(renewed at 60, two overlapping certificates per ceremony); the
gateway holds only the intermediate. In self-anchored mode (ADR-074,
a relay with no configured anchor) the gateway instead creates and
keeps the anchor key on its own host and issues itself the
intermediate. The relay answers `503` rather than serve anything
unsigned. An anchor replacement is published as a
rollover chain (`/v2/ohttp-anchor-rollover`): each record names the
new anchor and a commitment to the next backup and is signed by the
backup the previous step committed to; at most 16 links.

**B4. Client trust** (`accept_signed_key`). A client MUST accept a
record only when the anchor it holds (compiled in as
`PROD_OHTTP_ANCHOR`, or the one configured with the relay URL)
verifies the intermediate for `now`, the intermediate verifies
`(window, key_config)`, the window is within one of the current
window, the key id matches the window, and the record is not older
than a key it already holds for that relay nor a different key for a
window it holds (`Equivocation`). A record whose intermediate fails
under the held anchor is retried under the rollover chain, each link
checked against the previous anchor's commitment. There is no
unverified fallback; the lane `hostile_bootstrap_responses_fail_closed`
feeds poisoned key responses and expects zero direct requests.

**B5. The outer relay** (`vauchi-ohttp-relay`). A proxy on plain
TCP, behind the deployment's TLS-terminating proxy, whose only state
is in memory (the delayed answers and the rate-limit buckets below),
that forwards `POST /v2/ohttp` bodies of at most 128 KiB to the
gateway, refuses gateway replies over 128 KiB, propagates no client
header upstream, logs no client address, and caches the signed key
record for 300 s. It rate-limits per client IP in memory (50 requests
per second per IP by default) and evicts stale buckets; the IP is a
HashMap key and nothing else. **Delayed path** (`/v2/ohttp-async`,
vauchi/private#628): the client posts under a ticket it chose, the
outer relay forwards after a random delay of up to 900 s and holds the
encapsulated answer in memory until the client collects it on a later
poll, so the gateway sees the fetch long after the client's
connection. Losing the held answer costs a re-post, never mail: a
fetch only peeks. The outer relay advertises its window in a
`vauchi-ohttp-delay-window` header on every synchronous answer
(`advertised_delay_window`); a client that has seen it sends fetches
and acknowledgements through the delayed path and stays there until
the header is withdrawn (`delayed_window`, `fetch_path` in
`api/vauchi/sync_delayed.rs`). `RelayConfig::ohttp_delayed` only
forces the path where no advertisement exists, and a forced client
never falls back. The production outer relay advertises 900 s
(observed 2026-10-28), so shipped clients fetch through the delayed
path today.

**B6. No plaintext path.** A client MUST NOT send a data request to
the application relay directly. `post_action` (`http_transport.rs`)
checks only that OHTTP is active or `allow_direct` is set; the rule
that the outer relay's origin differs from the application relay's
lives in `sync_http.rs`, where `action_ohttp_route` gives a transport
OHTTP only through a distinct outer relay and `fetch_signed_ohttp_key`
refuses without one (`distinct_ohttp_route`, ADR-037 addendum
2026-07-04). Production never sets `allow_direct`, but
`fetch_signed_ohttp_key` honours it outside `cfg(feature = "testing")`
(`sync_http.rs:930`, vauchi/private#950). The key record is fetched
through the same outer hop. TLS to the outer relay MAY be pinned by
SPKI hash in addition to WebPKI (`tls_pinning.rs`); the production
configuration pins two SPKIs by default, the current outer relay's
and its dedicated host's (`api/config.rs`).

### State machine

Gateway key: `next` is generated a window ahead; at the window
boundary `current` becomes `previous` and stays accepted for one
window. Intermediate: valid 90 days, standby issued at day 60; the
anchor CLI's install step (`ohttp_install.rs`) refuses to install a
key and certificates that cannot sign today's window under the
expected anchor. A relay whose signer fails to load still starts and
answers `503` on `/v2/ohttp-key-signed`. Client held key: `None` →
accepted record → replaced only by a newer window or kept across a
failed refetch while the gateway still holds its window.

---

## Failure cases

The statuses below are those of the plain `/v2/*` routes. Over OHTTP
every handler error, including a wrong inner version, is an
encapsulated `200` whose JSON is `{ status: "error", error }`; any
non-2xx from the gateway (a `426`, a failed decapsulation or unpad,
bad inner JSON) reaches the client as a `502` from the outer relay.

- Rate limit or quota: `429` with `Retry-After`; the client retries
  later and its update stays pending.
- A send or register token that is not 64 hex characters, bad base64,
  a malformed body: `400`. Fetch and ack never validate tokens: an
  unknown token yields an empty page or `acknowledged: false`.
- Purge with a bad signature or stale timestamp: `401`; nothing is
  deleted (`a_purge_with_a_bad_signature_keeps_the_hints`).
- Gateway without a signed record: `503`; the client keeps its held
  key while the gateway still serves that window, else it fails
  closed.
- Outer relay down or the delayed answer lost: the request is
  re-posted; no mail is lost.
- Client below the minimum protocol version after the grace period:
  `426`.

## Security considerations

- **The relay does not learn the user's network address**, claim
  [S3](../claims.md), partial. The gateway sees requests from the
  outer relay only (`application_relay_observes_the_ohttp_relay_never_the_end_user`,
  lane RG-7), the outer relay sees addresses and HPKE ciphertext, the
  device-link chain makes no direct request to either hop
  (`device_link_chain_makes_zero_requests_to_either_hop`). Partial
  because one operator runs both hops in the alpha: the property
  holds against a single-host compromise and against third parties,
  not against the operator, and RG-7 closes on host separation until
  stage `release` (ADR-037 addendum 2026-09-08). The delayed path (B5)
  is what breaks the timing link a single observer of both hops could
  otherwise draw.
- **Public keys never route traffic**, claim [S4](../claims.md),
  partial. Mailboxes are 64-hex tokens derived per day from a shared
  key and the recipient's identity key (Card Update and Sync, B8);
  the relay keeps no key for mailbox routing (recovery proofs store an
  owner key), and a token from one day does not name the
  mailbox of the next. Partial: cross-day unlinkability is a design
  argument backed by `mailbox_token.spthy` in Core's round 8 and by
  the token tests, not by an experiment against the relay's logs; a
  mailbox *is* linkable within a day across its fetches, which is
  what the per-mailbox rate limit and quota rely on; and the
  **fetcher** is linkable across days. Each cycle the client fetches
  today's and yesterday's token of every contact in one request set
  (Card Update and Sync C1), so the sets of two consecutive days
  intersected in exactly yesterday's real tokens. The relay could
  chain one anonymous fetcher for as long as it kept fetching, count
  its contacts, see which of its mailboxes received blobs on which
  day, and tell the recurring real tokens from the random padding.
  Since core!2060 (vauchi/private#890, merged 2026-10-28)
  `registration_tokens_by_day` in `mailbox_token.rs` builds one
  padded batch set per day epoch and the adapter fetches each batch
  on its own (`fetch_chunks`), so no request spans two days; the
  relay is left with the timing of a day's requests, which the
  delayed path spreads, and the per-day overlap of the catch-up
  requests with the days they revisit, which is inherent to fetching
  an old token at all. Three
  routes are addressed
  by an identity key or its hash on purpose: guardian sets under
  `SHA-256(owner_pk || "guardians")`, recovery proofs under
  `SHA-256(old_pk)` and purge with the key itself (A7). And the
  rotation is not forward secure: tokens are deterministic in the
  shared key, the recipient's key and the day (Card Update and Sync
  B8), so a later compromise of a channel's shared key recomputes
  every past token of that channel; against a log the relay kept,
  unlinkability lasts only as long as the key's secrecy.
- **What the application relay learns.** Per blob: a token, a size
  (a padding bucket after the client's padding, a ladder rung on the
  way out), a time of arrival and of acknowledgement, an origin-hint
  blob when present, and the ratchet header inside the JSON it cannot
  read further. Per fetch: a set of up to 100 tokens that one client
  asked for together, which groups a user's contacts for that day.
  Per purge: an identity key, by the owner's choice.
- **What the outer relay learns.** The client's address, the times
  and sizes of its encapsulated requests, and which tickets it
  collects. It cannot open requests or answers.
- **What anyone can do.** Send to any token, which is why mailboxes
  have quotas and per-token rate limits
  (`a_flooded_mailbox_is_limited_while_another_is_still_served`);
  fetch any token, which yields ciphertext only and removes nothing.
  Sending is already a write by an outsider, and anyone who holds a
  token can do more: fetch learns its blob ids and ack deletes them one
  by one; a purge empties only the signing key's own mailbox (A7,
  since vauchi/private#944). Resource bounds are open as well, read in the
  code and not yet exercised (vauchi/private#945): a fetch's page is
  built in memory,
  `max_storage_bytes` only steers federation and is never enforced on
  send. Oversized legacy blobs are skipped and diagnosed as in A3.
  The shared and global rate-limit buckets let one client starve
  others, the purge nonce tracker can saturate, and the outer relay's
  delayed path holds answers in memory.
- **Key trust.** A compromised outer relay cannot substitute a gateway
  key: the client accepts only the anchor's chain, refuses an older
  window and refuses a second key for a held window. A compromised
  anchor is the trust root's limit; the rollover chain is how the
  owner moves away from it.

## Wire schema

The JSON bodies of every `/v2` request and response are in
[Wire Schemas](../schemas.md): generated from `vauchi-protocol`'s types
with the parser's length and item bounds written in, one example per
type, compared with Core's copy and validated in CI. The schema states
shape and bounds; the hex and base64 alphabets, the signature checks and
the token rules are this chapter's.

## Vectors

`mailbox_tokens` in [Test Vectors](../vectors.md) covers the tokens
the relay routes on. The signed key record, its two signing messages
and a rollover record are candidates; none exists yet.

## Sources

- `relay/src/http_api.rs`, `storage.rs`, `config.rs`, `rate_limit.rs`,
  `padding.rs`, `jitter.rs`, `version_policy.rs`, `handler/verify.rs`,
  `handler/nonce.rs`, `maintenance.rs`, `metrics.rs`
- `relay/src/ohttp_gateway.rs`, `ohttp_signer.rs`,
  `ohttp_window_keys.rs`, `ohttp_rollover.rs`, `ohttp_install.rs`
- `relay/src/federation_core.rs`, `federation_http.rs`,
  `federation_connector.rs`, `forwarding_hints.rs`, `integrity.rs`
- `vauchi-protocol/src/v2.rs`, `ohttp_key.rs`
- `ohttp-relay/src/lib.rs`, `config.rs`, `router.rs`, `delayed.rs`,
  `rate_limit.rs`, `signed_key_cache.rs`, `upstream.rs`
- `vauchi-core/src/network/ohttp_client.rs`, `http_transport.rs`,
  `http_transport/delayed.rs`, `http_adapter.rs`, `tls_pinning.rs`,
  `crypto/ohttp_key_trust.rs`, `api/vauchi/sync_http.rs`,
  `api/config.rs`
- `e2e/tests/it/ohttp_source_address.rs`, `ohttp_integration.rs`,
  `ohttp_fail_closed_matrix.rs`, `action_family_oracles.rs`
- ADR-029 (tokens), ADR-037 and addenda (OHTTP, single operator,
  trust root), ADR-052 (federation)
