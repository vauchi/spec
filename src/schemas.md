<!-- SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Wire Schemas

The relay's `/v2` requests and responses are JSON bodies. Their schema
below is generated from the Rust types in `vauchi-protocol/src/v2.rs`
by Core's `wire_schema_tests.rs`, together with one example per type,
and both are checked rather than written: Core's test fails when the
committed files no longer match what the types generate, and this
book's CI fails when its copy differs from Core's or when an example
stops validating against the schema (`check:wire-schema`). The
canonical files live in Core at `vauchi-protocol/schemas/`.

What the schema states, and what it does not:

- **Shape.** Every field, its JSON type, which fields are required and
  which may be absent or `null`, as `serde` reads them.
- **Bounds.** The `maxLength` and `maxItems` values are the parser's:
  the deserializers refuse a longer string or list before any handler
  runs, and Core's `every_published_bound_is_the_parsers_bound` proves
  each one by parsing a value at the bound and one past it. Lengths are
  bytes; every bounded field is ASCII, so the count is the same in
  characters.
- **Not charsets.** Hex and base64 fields are described in the
  [Relay](protocols/relay.md) chapter, but the parse boundary does not
  check the alphabet, and the schema does not claim it does.
- **Not closed objects.** Unknown fields are accepted and ignored, as
  the parser does; the schema leaves `additionalProperties` open.
- **Not meaning.** Whether a signature verifies, a token is today's or
  a hash names a stored proof is the handler's decision, written in the
  chapter's normative operations, not in the schema.

The examples are inputs the parser accepts; they are not transcripts of
a live relay. The signed OHTTP key record and the escrow messages are
not in this schema yet.

Download: [relay-wire-v2.schema.json](schemas/relay-wire-v2.schema.json),
[relay-wire-v2-examples.json](schemas/relay-wire-v2-examples.json)

## Examples

```json
{{#include schemas/relay-wire-v2-examples.json}}
```

## Schema

```json
{{#include schemas/relay-wire-v2.schema.json}}
```
