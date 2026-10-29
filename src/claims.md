<!-- SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Security Claims

These are the claims a reviewer is invited to falsify. Each one names its attacker, states one sentence, says what a user loses if the sentence is false, and points to what backs it. Numbers are permanent; see [Conventions](conventions.md). Statuses: **shipped**, **partial** (the entry says what is missing), **planned**.

Proof pointers name test functions and lanes in [vauchi/core](https://gitlab.com/vauchi/core) and [vauchi/e2e](https://gitlab.com/vauchi/e2e), and lemmas in Core's `vauchi-core/verification/` and `vauchi-app/verification/`. Lemma names that end in a behaviour, such as `qr_leak_exposes_seed`, are exists-trace lemmas: they prove that the attack exists in the model, and are published on purpose.

The link runs both ways. Every test, lemma and invariant named here carries the comment `@claim: S<n>` where it is defined, and CI fails when an annotation names a claim this chapter does not have or when a shipped or partial claim has no annotation left (`check:claim-annotations`, in this book and in Core's `check:spec-names`). A claim cannot outlive its last proof, and a proof cannot point at a claim that is gone.

Extracted on 2026-10-28 from the security-claims page of vauchi.app/docs, itself verified against Core `main` that week. Every *Section* link leads to an extracted chapter; where a chapter found the code weaker than the claim's sentence, its security considerations say so and the claim's entry is the one to read next.

## S1. The relay cannot read a contact card or an update

- **Attacker**: Relay operator with its database and logs.
- **Statement**: Every card and update is encrypted on the sender's device for one recipient; the relay stores and forwards bytes it cannot open.
- **If false**: A relay operator, or anyone who copies its database, reads contact data.
- **Status**: shipped
- **Backed by**: lane `test:release-rg6-observability`, case `integration_ohttp_relay_observations_exclude_update_content`; Tamarin `card_update.spthy`, lemma `changes_stay_secret`
- **Section**: [update-and-sync](protocols/update-and-sync.md)

## S2. An update is from the contact it claims, applied once, never rolled back

- **Attacker**: Relay operator.
- **Statement**: A relay that replays an old update, swaps the sender or serves a stale version cannot change what the recipient ends up with.
- **If false**: A relay rewrites a contact's card, or reverts a revoked field.
- **Status**: shipped
- **Backed by**: Tamarin `card_update.spthy`, lemmas `update_comes_from_the_sender_for_this_recipient` and `each_update_is_applied_once`; tests `test_crypto_hardening_ratchet_same_chain_auth_failure_rolls_back_state` and `test_crypto_hardening_ratchet_new_dh_auth_failure_rolls_back_state` in `crypto_ratchet_tests.rs`. The third sentence, no rollback, rests on the version floor in code: `stale_version_delta_rejected_by_device_receiver` in `sync_card_update_tests.rs`, `delta_version_floor_is_tracked_per_peer_device` in `sync_card_update_device_floor_tests.rs` and `genesis_card_per_device_floor_accepts_each_device_and_rejects_its_own_stale_version`. The model's `no_rollback` lemma is falsified without the floor and reaches no verdict with it (Card Update and Sync, security considerations), so it is stated, not proved.
- **Section**: [update-and-sync](protocols/update-and-sync.md)

## S3. The relay does not learn the user's network address

- **Attacker**: Relay operator; separately, the OHTTP gateway operator.
- **Statement**: Clients reach the relay through Oblivious HTTP: the gateway sees the address but not the content, the relay the content but not the address; nothing in Core talks to the relay without that hop.
- **If false**: The relay maps mailboxes to IP addresses and so to people and places.
- **Status**: partial
- **Backed by**: lane `test:release-rg7`, case `application_relay_observes_the_ohttp_relay_never_the_end_user`; lane `test:release-rg8`, cases `device_link_chain_makes_zero_requests_to_either_hop` and `hostile_bootstrap_responses_fail_closed`; test `content_is_never_fetched_without_ohttp` in `content_over_ohttp_tests.rs`. Partial: until the first release one operator runs both hops.
- **Section**: [relay](protocols/relay.md)

## S4. Public keys never route traffic

- **Attacker**: Relay operator with full logs.
- **Statement**: Mailboxes are addressed by tokens that rotate daily; a log holds tokens, not identities, and a token from one day does not name the same mailbox the next. The statement is about mailboxes; three other relay routes are addressed by an identity key or its hash and are listed under *Partial*.
- **If false**: The relay links mailboxes to identities and across days, and builds the contact graph.
- **Status**: partial
- **Backed by**: tests `unsolicited_tokens_are_rejected_for_immediate_fetches`, `unsolicited_tokens_are_rejected_for_delayed_fetches` and `unattributed_blobs_are_not_delivered_or_acknowledged` in `delayed_mailbox_routing_tests.rs`. Partial, three ways. Cross-day unlinkability of a *mailbox* is a design argument (and, in Core's round-8 models, `mailbox_token.spthy`) without a dedicated experiment. The *fetcher* was linkable across days on Core `main` as extracted: each cycle fetched today's and yesterday's token for every contact in one request set, so consecutive days' sets overlapped in yesterday's real tokens and the relay could chain one anonymous fetcher for as long as it fetched, and tell its padding from its real tokens (Relay, security considerations). core!2060 (vauchi/private#890, merged 2026-10-28) groups registration and fetch requests per day epoch (`registration_batches_hold_the_tokens_of_one_day_each`, `a_fetch_request_never_spans_two_registration_batches`, `two_registration_batches_post_two_tickets_and_both_answers_are_collected`), so no request carries two days' tokens; what remains is the timing of a day's requests on the immediate path, which the delayed path spreads. And guardian sets, recovery proofs and purge requests are addressed by the owner's identity key or its hash (Social Recovery A4 and B3, Relay A7): a stable, identity-bound address on the relay, by design, so that contacts can find a recovery and so that deletion is the identity's own act.
- **Section**: [relay](protocols/relay.md)

## S5. Message sizes are padded

- **Attacker**: Relay operator, or a network observer.
- **Statement**: Ciphertexts are padded to fixed buckets before encryption, so the relay sees bucket sizes rather than exact lengths.
- **If false**: Card contents or update kinds are inferred from lengths.
- **Status**: partial
- **Backed by**: tests `test_pad_unpad_roundtrip_small`, `test_pad_overflow_alignment` and `test_pad_very_large_message` in `crypto/padding.rs`, the Kani proof `unpad_never_panics_and_only_accepts_a_prefixed_plaintext` in `crypto/padding_proofs.rs`, and `an_empty_message_unpads_from_a_bare_length_prefix` in `crypto_tests.rs`. Partial: the claim that buckets defeat a traffic-analysis attacker has not been measured against one.
- **Section**: [update-and-sync](protocols/update-and-sync.md)

## S6. Watching the QR exchange does not give the session key

- **Attacker**: Someone who sees both screens or records the QR codes.
- **Statement**: The two devices run a key agreement bound to both identity keys; a transcript of the QR codes alone yields no key, and a key agreed with the wrong identity fails.
- **If false**: A bystander who photographs the exchange reads the cards exchanged.
- **Status**: shipped
- **Backed by**: Tamarin `qr_exchange.spthy`, lemmas `session_key_secrecy` and `no_misbinding` (falsified under `-DNO_IDENTITY_BINDING`); tests `test_transcript_binding_includes_identity_keys` and `test_transcript_binding_includes_ephemeral_keys` in `exchange_ceremony_tests.rs`, which exercise the symmetric derivation `vauchi-x3dh-symmetric-v2` the QR exchange uses (In-Person Exchange A4). The tests `test_x3dh_identity_binding_wrong_key_fails`, `test_x3dh_zero_identity_rejected` and `test_x3dh_full_bidirectional_agreement` in `exchange_x3dh_tests.rs` exercise the two-DH agreement of the relay-mediated exchange (Link and Relay-Mediated Exchange B2), not this one.
- **Section**: [in-person-exchange](protocols/in-person-exchange.md)

## S7. A confirmation means the other side really confirmed

- **Attacker**: Someone in the relay path, or who learned a shared key.
- **Statement**: Reciprocity tokens prove the peer completed the exchange; a leaked shared key is not enough to forge one, the identity key is also needed.
- **If false**: A user is told an exchange completed when it did not.
- **Status**: partial
- **Backed by**: Tamarin `reciprocity.spthy`, lemmas `confirmed_means_the_peer_confirmed` and `a_leaked_shared_key_also_needs_the_identity_key`, which model the relay-sync tier (In-Person Exchange D3). Partial: the identity signature exists on that tier only. The Glance tier (B13) authenticates the confirmation with the session key alone, so whoever holds that key forges it; the escrow tier (D2) compares a token derived from the exchange's raw DH output. On those two tiers the second sentence of the statement does not hold, and the confirmation is only as strong as the exchange's own secrecy (S6).
- **Section**: [in-person-exchange](protocols/in-person-exchange.md)

## S8. Over Bluetooth, the scanner connects to the device it scanned

- **Attacker**: A nearby device within radio range.
- **Statement**: The advertisement binds the radio session to the QR the user scanned, so a nearby device cannot step into the exchange.
- **If false**: A stranger's device completes an exchange meant for the person in front of you.
- **Status**: shipped
- **Backed by**: Tamarin `ble_advertisement.spthy`, lemma `scanner_connects_to_the_displayer_it_scanned`
- **Section**: [in-person-exchange](protocols/in-person-exchange.md)

## S9. A remote exchange over a link is weaker, and says so

- **Attacker**: Anyone who obtains the link before its recipient.
- **Statement**: A card can be exchanged by sending a link; the link carries a signed bootstrap and the result is a live contact with a shared key. Today whoever opens the link first becomes a contact, with no approval by the sender and no out-of-band code.
- **If false**: A link forwarded or intercepted makes a stranger a contact of the sender without the sender noticing.
- **Status**: partial
- **Backed by**: test `v2_two_party_completes_to_a_live_exchanged_link_contact_with_symmetric_key` in `complete_link_exchange_tests.rs`; `derive_sas` in `relay_exchange_tests.rs` (the 6-digit code exists only for the relay-mediated exchange); Core's `link_exchange.spthy` (round 8) shows `contact_only_after_approval` falsified today. Sender approval and an out-of-band code are tracked as open work.
- **Section**: [link-exchange](protocols/link-exchange.md)

## S10. Trust level follows how you exchanged, and cannot be edited

- **Attacker**: A user, through the app, trying to raise a contact's trust.
- **Statement**: The trust shown for a contact is derived from the exchange facts: transport, proximity evidence, and whether the user compared key fingerprints out of band; there is no control to set a level by hand.
- **If false**: A contact is shown as verified without the evidence.
- **Status**: shipped
- **Backed by**: test `the_trust_shown_follows_the_exchange_and_cannot_be_tapped` in `contact_trust_tests.rs` (vauchi-app). The test proves the absence of a control; software that can write the database can change the stored exchange facts the derivation reads (Keys and Cards G3), and nothing here claims otherwise.
- **Section**: [keys-and-cards](protocols/keys-and-cards.md)

## S11. Old messages stay secret after a compromise

- **Attacker**: Someone who recorded relay or network traffic and later obtains a device's keys, or a copy of its storage, taken at a point in time.
- **Statement**: Each update between contacts uses a key deleted after use; taking the current ratchet state does not open earlier updates, and the channel heals once a fresh exchange of ephemeral keys happens.
- **If false**: Recorded traffic plus a later compromise of the phone reveals every update ever received.
- **Status**: partial
- **Backed by**: tests `test_dr_forward_secrecy`, `test_forward_secrecy_compromised_state` and `test_dr_skipped_message_limit` in `crypto_ratchet_tests.rs`. Partial: two paths have no forward secrecy and the statement does not cover them. The first genesis message of a session (Card Update and Sync C5) resumes it at the first reply; every device-to-device sync batch (E2) is encrypted under a static-to-static agreement, so a later compromise of either device's exchange key opens every recorded batch, and those batches carry contacts, cards and ratchet states.
- **Section**: [update-and-sync](protocols/update-and-sync.md)

## S12. Destroying the storage key makes the data unrecoverable

- **Attacker**: Someone with the device's storage after the key was wiped.
- **Statement**: Everything at rest is encrypted under a hierarchy rooted in one storage master key in the platform's secure storage; wiping that key wipes the data, and one identity's keys never open another's.
- **If false**: A wiped or shredded app still yields its data to forensics.
- **Status**: partial
- **Backed by**: tests `test_smk_destruction_makes_data_irrecoverable`, `test_shredding_isolation_across_identities` and `test_fkek_protects_file_keys` in `crypto_shredding_integration_tests.rs`; lane `test:release-rg8`, case `hard_shred_after_grace_fanout_over_outer_hop_only`. Partial: on Android and iOS the key destruction step is incomplete; the fix is in testing.
- **Section**: [keys-and-cards](protocols/keys-and-cards.md)

## S13. A backup without its password reveals nothing

- **Attacker**: Someone holding the backup file.
- **Statement**: Backups are encrypted with a key derived from the password; the file never contains key material in the clear, and a wrong password fails rather than yielding garbage.
- **If false**: A backup in cloud storage exposes the identity and, for the full backup that is the default today, every contact's shared key, card and visibility rules.
- **Status**: shipped
- **Backed by**: tests `v2_backup_encrypts_the_seed_and_leaks_no_key_material`, `test_v2_wrong_password` and `backup_debug_output_carries_no_secrets_or_contact_data` in `backup_format_versioning_tests.rs` and `backup_boundary_tests.rs`; for the v6 file the app writes today, `backup_v6_vector_decrypts_under_its_header_and_not_under_a_changed_one` and `backup_v6_vector_imports_with_production_argon2id_and_refuses_a_wrong_password` in `protocol_test_vectors_tests.rs`; vectors entries `backup` (v3) and `backup_v6`. The claim is about the file; its strength against guessing is the password through Argon2id, and only the identity-only v2 export checks the password's strength today: the full backup accepts any password (Keys and Cards D5, vauchi/private#891).
- **Section**: [keys-and-cards](protocols/keys-and-cards.md)

## S14. A duress unlock shows a decoy and sends nothing that reveals it

- **Attacker**: Someone forcing the user to unlock, and watching the network.
- **Statement**: Unlocking with the duress PIN opens a decoy; anything sent afterwards has the shape of normal traffic, cover items carry the length and timestamp of the real item they stand for, and applying one changes nothing on a linked device.
- **If false**: The coercer learns from the app or the traffic that a duress code was used.
- **Status**: partial
- **Backed by**: tests `applying_a_cover_item_changes_nothing` and `a_cover_item_has_the_length_and_timestamp_of_the_item_it_stands_for` in `duress_cover_tests.rs`. Partial: the Tamarin model `duress_cover.spthy` is scaffolded and states no lemma yet.
- **Section**: [keys-and-cards](protocols/keys-and-cards.md)

## S15. A linked device is a full copy of the identity

- **Attacker**: Someone who photographs the link QR, or who obtains it.
- **Statement**: Linking a device transfers the identity seed; a photograph of the link QR alone does not give it away, a leaked link QR does and lets the attacker choose which device identity joins; the QR expires after five minutes.
- **If false**: A leaked link QR gives away the whole identity; this is stated, not hidden.
- **Status**: shipped
- **Backed by**: Tamarin `device_link.spthy`, lemmas `seed_secrecy`, `photographed_qr_alone_keeps_the_seed`, `initiator_agreement`, `joiner_agreement`, and the attack lemmas `qr_leak_exposes_seed` and `qr_leak_lets_attacker_choose_joiner_identity`; Quint `device_link_machines.qnt`, invariants `joiner_seed_implies_registered` and `no_device_registered_for_a_failed_joiner`. Per-device subkeys that would contain a leak are planned.
- **Section**: [keys-and-cards](protocols/keys-and-cards.md)

## S16. Accepting a recovery needs the real recovery

- **Attacker**: Someone who tells your contacts you lost your phone, with the old device or not.
- **Statement**: A contact only rekeys with a recovering user whose recovery was genuinely initiated, and the recovered key stays secret from the contact who accepts it.
- **If false**: An impostor takes over a contact's channel by claiming a recovery.
- **Status**: partial
- **Backed by**: Tamarin `recovery_acceptance.spthy`, lemmas `accept_needs_the_real_recovery`, `john_key_secrecy`, `alice_rekeys_only_with_an_accepting_contact`, and the attack lemma `a_stranger_can_rekey_with_the_recovering_user`. Partial: a contact who accepts a recovery proof does not yet receive a key bound to the recovered identity; the fix is in progress.
- **Section**: [social-recovery](protocols/social-recovery.md)

## S17. Social recovery needs the guardians, and only the real ones

- **Attacker**: Someone impersonating a guardian or the recovering user.
- **Statement**: Restoring from guardians needs the threshold of guardians' shares; a member of the same recovery group can stand in for an absent guardian; each side rekeys only with the real counterpart.
- **If false**: A single guardian, or an impostor, recovers someone else's identity.
- **Status**: partial
- **Backed by**: Tamarin `social_recovery.spthy`, lemmas `backup_needs_both_guardians` and `a_group_mate_can_stand_in` for the first two sentences, with the Shamir split, sealing, response and restore as Core API under test (Social Recovery A). Partial: the third sentence is backed by `john_rekeys_only_with_the_real_alice` and `alice_rekeys_only_with_the_real_john`, which model the rekey of Social Recovery C, a design that is not in the code; and the app does not yet export a guardian backup on designation or hand shares to guardians (vauchi/private#796).
- **Section**: [social-recovery](protocols/social-recovery.md)

## Not claimed

Limits known today, so that a reviewer does not spend a week proving them:

- The relay sees metadata: which mailbox tokens receive how much, and when. Sealed sender and padding reduce it; they do not remove it.
- The relay can correlate one fetcher's per-day requests by their timing on the immediate path; the delayed path spreads it. Until core!2060 (merged 2026-10-28) the requests also overlapped in yesterday's tokens across days, which made the fetcher a stable pseudonym (S4).
- Three relay routes are addressed by an identity key or its hash: guardian sets, recovery proofs and purge. A recovery is visible metadata to the relay by design.
- Token unlinkability is not forward secure: a mailbox token is a deterministic function of the channel's shared key, the recipient's key and the day, so whoever later obtains a contact's shared key can recompute every past token of that channel and link them in a retained log (S4).
- Device-to-device sync has no forward secrecy: a later compromise of a device's exchange key opens every recorded batch, and batches carry contacts, cards and ratchet states (S11).
- The full backup, the default, accepts any password; only the identity-only export checks strength (S13, vauchi/private#891).
- A duress PIN is six digits. Its Argon2id hash in storage is brute-forceable offline in about a million guesses, so someone who images the device learns whether a duress PIN exists and what it is; duress protects against a coercer who watches, not one who extracts the storage, and the latter already holds the data (Keys and Cards F).
- A compromised device exposes the whole identity seed. Subkeys are planned.
- There is no key transparency log. A relay that hands out a wrong key for a first contact is not auditable today; a signed log is planned.
- The key agreement is not post-quantum. Recorded ciphertext could be read by a future quantum computer; a hybrid ML-KEM scheme is planned.
- No external cryptographic audit has been performed. It is planned and depends on funding.
