<!-- SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Vauchi Protocol Specification

The Vauchi protocols as shipped, written by extraction from the code:
normative chapters, numbered falsifiable claims, test vectors, and the
disclosure policy. Rendered with mdBook; published from `main` and from
tags (`0.1-draft` first).

- Read: the rendered book, or start at `src/index.md`.
- Build: `mdbook build` (mdbook 0.4.x).
- Check: `markdownlint 'src/**/*.md' --config .markdownlint.json`;
  CI also compares `src/vectors/` with Core's canonical vectors.
- Report a finding: see `src/disclosure.md`.

Decision and rules: ADR-076 in the project's private decisions, summarised
in `src/conventions.md`. Code: [vauchi/core](https://gitlab.com/vauchi/core),
[vauchi/relay](https://gitlab.com/vauchi/relay).
