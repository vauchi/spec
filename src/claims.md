<!-- SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- description: The security claims a reviewer is invited to falsify: each names its attacker, what a user loses if it is false, its status and the test or lemma behind it. -->

# Security Claims

These are the claims a reviewer is invited to falsify. Each one names its attacker, states one sentence, says what a user loses if the sentence is false, and points to what backs it. Numbers are permanent; see [Conventions](conventions.md). Statuses: **shipped**, **partial** (the entry says what is missing), **planned**.

Proof pointers name test functions and lanes in [vauchi/core](https://gitlab.com/vauchi/core) and [vauchi/e2e](https://gitlab.com/vauchi/e2e), and lemmas in Core's `vauchi-core/verification/` and `vauchi-app/verification/`. Lemma names that end in a behaviour, such as `qr_leak_exposes_seed`, are exists-trace lemmas: they prove that the attack exists in the model, and are published on purpose.

The link runs both ways. In Core, the tests, lemmas and invariants named here carry the comment `@claim: S<n>` where they are defined, with gaps an entry names where it cites them, and in the end-to-end repository the lane cases S1, S3 and S12 name carry it too (e2e!288). CI fails when an annotation names a claim this chapter does not have or when a shipped or partial claim has no annotation left (`check:claim-annotations`, in this book and in Core's `check:spec-names`). A claim cannot outlive its last proof, and a proof cannot point at a claim that is gone.

Extracted on 2026-10-28 from the security-claims page of vauchi.app/docs, itself verified against Core `main` that week. Every *Section* link leads to an extracted chapter; where a chapter found the code weaker than the claim's sentence, its security considerations say so and the claim's entry is the one to read next.

## S1. The relay cannot read a contact card or an update

- **Attacker**: Relay operator with its database and logs.
- **Statement**: Every card and update is encrypted on the sender's device for one recipient; the relay stores and forwards bytes it cannot open.
- **If false**: A relay operator, or anyone who copies its database, reads contact data.
- **Status**: shipped
- **Backed by**: lane `test:release-rg6-observability`, case `integration_ohttp_relay_observations_exclude_update_content`, which shows only that the relay's logs and metrics hold no marker sent in an update; Tamarin `card_update.spthy`, lemma `changes_stay_secret`, falsified by its control `-DPLAINTEXT_UPDATES`.
- **Section**: [update-and-sync](protocols/update-and-sync.md)

## S2. An update is from the contact it claims, applied once, never rolled back

- **Attacker**: Relay operator.
- **Statement**: A relay that replays an old update, swaps the sender or serves a stale version cannot change what the recipient ends up with.
- **If false**: A relay rewrites a contact's card, or reverts a revoked field.
- **Status**: partial
- **Backed by**: Tamarin `card_update.spthy`, lemmas `update_comes_from_the_sender_for_this_recipient`, falsified by its control `-DNO_RECIPIENT_BINDING`, and `each_update_is_applied_once`. The second has no control that removes its nonce check, because the prover reaches no verdict without it; the witness `a_leaked_sender_key_applies_one_update_twice` under `-DSENDER_KEY_LEAKS` shows that two applications of one update are reachable in the model, so the lemma does not hold for want of traces. Tests `test_crypto_hardening_ratchet_same_chain_auth_failure_rolls_back_state` and `test_crypto_hardening_ratchet_new_dh_auth_failure_rolls_back_state` in `crypto_ratchet_tests.rs`. The third sentence, no rollback, rests on the version floor in code: `stale_version_delta_rejected_by_device_receiver` in `sync_card_update_tests.rs`, `delta_version_floor_is_tracked_per_peer_device` in `sync_card_update_device_floor_tests.rs` and `genesis_card_per_device_floor_accepts_each_device_and_rejects_its_own_stale_version` in `genesis_card_per_device_floor_tests.rs`. Per-device floors alone did not prevent a held sibling-device addition, removal or name from overwriting newer state. Persistent per-field ordering and tombstones now prevent those cases, covered by `peer_card_ordering_blocks_held_add_on_both_receive_paths` and `peer_card_ordering_blocks_held_removal_and_name_on_both_receive_paths` in `peer_card_ordering_tests.rs`. It trusts signed source clocks, cannot reconstruct pre-upgrade deletion history, and does not yet preserve ordering state through backup restoration. Withholding can still hide the newer state. The model's `no_rollback` lemma is falsified without the floor and reaches no verdict with it (Card Update and Sync, security considerations), so it is stated, not proved.
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
- **Backed by**: tests `unsolicited_tokens_are_rejected_for_immediate_fetches`, `unsolicited_tokens_are_rejected_for_delayed_fetches` and `unattributed_blobs_are_not_delivered_or_acknowledged` in `delayed_mailbox_routing_tests.rs`; test `test_contact_mailbox_token_rotates_daily` in `mailbox_token_tests.rs` and Tamarin `mailbox_token.spthy`, a diff model of a mailbox's next-day token against another mailbox's that `test:formal` verifies and falsifies under `-DSTABLE_TOKEN` (neither annotated yet). Partial, three ways. Cross-day unlinkability of a *mailbox* rests on that model and test, without an experiment against a relay. The *fetcher* was linkable across days on Core `main` as extracted: each cycle fetched today's and yesterday's token for every contact in one request set, so consecutive days' sets overlapped in yesterday's real tokens and the relay could chain one anonymous fetcher for as long as it fetched, and tell its padding from its real tokens (Relay, security considerations). core!2060 (vauchi/private#890, merged 2026-10-28) groups registration and fetch requests per day epoch (`registration_batches_hold_the_tokens_of_one_day_each`, `a_fetch_request_never_spans_two_registration_batches`, `two_registration_batches_post_two_tickets_and_both_answers_are_collected`), so no request carries two days' tokens; what remains is the timing of a day's requests on the immediate path, which the delayed path spreads. And guardian sets, recovery proofs and purge requests are addressed by the owner's identity key or its hash (Social Recovery A4 and B3, Relay A7): a stable, identity-bound address on the relay, by design, so that contacts can find a recovery and so that deletion is the identity's own act.
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
- **Backed by**: Tamarin `qr_exchange.spthy`, lemmas `session_key_secrecy` and `no_misbinding` (falsified under `-DNO_IDENTITY_BINDING`); tests `test_transcript_binding_includes_identity_keys` and `test_transcript_binding_includes_ephemeral_keys` in `exchange_ceremony_tests.rs`, which exercise the symmetric derivation `vauchi-x3dh-symmetric-v2` the QR exchange uses (In-Person Exchange A4). The tests `test_x3dh_identity_binding_wrong_key_fails`, `test_x3dh_zero_identity_rejected` and `test_x3dh_full_bidirectional_agreement` in `exchange_x3dh_tests.rs` carry `@claim: S6`, but they exercise the two-DH agreement of the relay-mediated exchange (Link and Relay-Mediated Exchange B2), not this one, so their annotation overstates what they back here.
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
- **Statement**: The advertisement binds the radio session to the QR the user scanned and the handshake pins the displayer's identity, so a nearby device cannot step into the exchange in the displayer's place.
- **If false**: A stranger's device completes an exchange meant for the person in front of you.
- **Status**: partial
- **Backed by**: Tamarin `ble_advertisement.spthy`, lemma `scanner_connects_to_the_displayer_it_scanned`, whose premise has an honest `Advertise(D, x)`: it says which displayer an honest advertiser is, not that a device replaying a photographed prefix is turned away; Tamarin `ble_handshake.spthy`, lemma `scanner_binds_the_displayer`, verified and falsified under `-DRADIO_ONLY` in the nightly `test:formal-extended` (not annotated yet), which is where the scanner pins the displayer. Partial: the displayer does not pin the scanner; CI asserts `displayer_binds_the_scanner` falsified, by default and under `-DQR_PRIVATE`. The card identity is checked against the wire identity, but an unpinned peer is not proven to own that identity (vauchi/private#941).
- **Section**: [in-person-exchange](protocols/in-person-exchange.md)

## S9. A remote exchange over a link is weaker, and says so

- **Attacker**: Anyone who obtains the link before its recipient, without the code the sender sends another way.
- **Statement**: A card can be exchanged by sending a link and a six-digit code; the result is a live contact with a shared key, marked `Remote`. Whoever holds the link and not the code gets one guess per link, one in a million, and cannot test guesses offline. This holds only if the code travels another way than the link, which the copy can only ask for, and `spake2` has not been independently audited.
- **If false**: A link forwarded or intercepted makes a stranger a contact of the sender without the sender noticing.
- **Status**: partial
- **Backed by**: tests `a_wrong_code_leaves_the_two_sides_in_different_gates` in `link_mode_tests.rs`, `a_wrong_code_makes_no_contact_on_either_side_and_uses_up_the_link` in `link_exchange_api_tests.rs`, `a_link_of_no_supported_version_is_refused` and `the_link_holds_nothing_but_its_key_nonce_version_and_name` in `link_mode_tests.rs`; `v2_two_party_completes_to_a_live_exchanged_link_contact_with_symmetric_key` in `complete_link_exchange_tests.rs`; the bootstrap signature covers the card and the exchange (`link_bootstrap_signature_covers_the_card` and `link_bootstrap_signature_is_bound_to_its_exchange`, also in `complete_link_exchange_tests.rs`), and a second opener is told the link was used (`a_second_person_opening_a_used_link_is_told_it_was_used` in `link_exchange_api_tests.rs`); Core's `link_exchange.spthy` shows `contact_only_after_approval` verified on the shipped protocol, with the one winning guess excepted, assuming SPAKE2's messages offer no offline test.
- **Section**: [link-exchange](protocols/link-exchange.md)

## S10. Trust level follows how you exchanged, and cannot be edited

- **Attacker**: A user, through the app, trying to raise a contact's trust.
- **Statement**: The trust shown for a contact is derived from the exchange facts: transport, proximity evidence, and whether the user compared key fingerprints out of band; there is no control to set a level by hand.
- **If false**: A contact is shown as verified without the evidence.
- **Status**: shipped
- **Backed by**: test `the_trust_shown_follows_the_exchange_and_cannot_be_tapped` in `contact_trust_tests.rs` (vauchi-app). The test proves the absence of a control and covers only the fingerprint flag (Standard against Verified), not transport or proximity. That flag is set by the user's own confirm button (`confirm_match` in vauchi-app `fingerprint_verify.rs`): it records that the user said the fingerprints matched, which the app cannot check. Software that can write the database can change the stored exchange facts the derivation reads (Keys and Cards G3), and nothing here claims otherwise.
- **Section**: [keys-and-cards](protocols/keys-and-cards.md)

## S11. Old messages stay secret after a compromise

- **Attacker**: Someone who recorded relay or network traffic and later obtains a device's keys, or a copy of its storage, taken at a point in time.
- **Statement**: Each update between contacts uses a key deleted after use; taking the current ratchet state does not open earlier updates, and the channel heals once the device has made a new ratchet key after the theft and the contact has used it.
- **If false**: Recorded traffic plus a later compromise of the phone reveals every update ever received.
- **Status**: partial
- **Backed by**: tests `test_dr_forward_secrecy`, `test_forward_secrecy_compromised_state`, `test_dr_skipped_message_limit` and `a_stolen_state_stops_opening_messages_after_the_device_uses_a_key_made_later` in `crypto_ratchet_tests.rs`. The last one backs healing and shows its window: the stolen state still opens the contact's next message after the device's first reply, because the key that reply carries was in the stolen state, and opens nothing the contact sends after the device's second reply. Healing takes messages in both directions; no test covers a channel where one side stays silent. Partial: two paths have no forward secrecy and the statement does not cover them. The first genesis message of a session (Card Update and Sync C5) resumes it at the first reply; every device-to-device sync batch (E2) is encrypted under a static-to-static agreement, so a later compromise of either device's exchange key opens every recorded batch, and those batches carry contacts, cards and shared contact keys. They do not copy live ratchet states; each device bootstraps its own pairwise sessions. Ratchet states are sealed under the background receive key (S12), which the platform yields after the first unlock since boot even while the phone is locked, so a copy taken from such a phone includes the current ratchet state: the case the statement covers, and earlier updates stay closed.
- **Section**: [update-and-sync](protocols/update-and-sync.md)

## S12. Destroying the storage key makes the data unrecoverable

- **Attacker**: Someone with the device's storage after the key was wiped.
- **Statement**: Everything at rest is encrypted under keys in the platform's secure storage: one storage master key for all of it but the receive state, and a random background receive key for the receive state a locked phone advances (ratchet states and the mailbox tokens stored ahead). Every shred wipes both; wiping them wipes the data, and one identity's keys never open another's.
- **If false**: A wiped or shredded app still yields its data to forensics.
- **Status**: shipped
- **Backed by**: tests `test_smk_destruction_makes_data_irrecoverable`, `test_shredding_isolation_across_identities` and `test_fkek_protects_file_keys` in `crypto_shredding_integration_tests.rs`; lane `test:release-rg8`, case `hard_shred_after_grace_fanout_over_outer_hop_only`; tests `every_shred_destroys_the_brk_with_the_smk` in `background_receive_key_tests.rs`, `a_ratchet_saved_under_the_receive_key_needs_that_key_to_load` in `receive_key_sealing_tests.rs` and `no_stored_token_is_readable_on_disk` in `receive_tokens_ahead_tests.rs`; on Android and iOS, the shells' shred tests (ShredDestroysTheStorageKeyTest, ShredDestroysTheStorageKeyTests: a copy of the data taken before a shred no longer opens afterwards, vauchi/private#580).
- **Section**: [keys-and-cards](protocols/keys-and-cards.md)

## S13. A backup without its password reveals nothing

- **Attacker**: Someone holding the backup file.
- **Statement**: Backups are encrypted with a key derived from the password; the file never contains key material in the clear, and a wrong password fails rather than yielding garbage.
- **If false**: A backup in cloud storage exposes the identity and, for the full backup that is the default today, every contact's shared key, card and visibility rules; for a v7 file of an install with a duress PIN, also the mask identity, the decoys and both credential hashes, which a 6-digit duress PIN does not protect offline (Keys and Cards D4; without biometric unlock both credentials are real passwords, ADR-032 amended 2026-11-10). A decoy payload under its own password holds the mask profile only.
- **Status**: shipped
- **Backed by**: tests `v2_backup_encrypts_the_seed_and_leaks_no_key_material`, `test_v2_wrong_password` and `backup_debug_output_carries_no_secrets_or_contact_data` in `backup_format_versioning_tests.rs` and `backup_boundary_tests.rs`; for the v7 file the app writes today, `backup_v7_vector_opens_its_real_payload_under_its_header_only` and `backup_v7_vector_imports_with_production_argon2id_and_refuses_a_wrong_password` in `protocol_test_vectors_backup_v7_tests.rs`; for the v6 file it still imports, `backup_v6_vector_decrypts_under_its_header_and_not_under_a_changed_one` and `backup_v6_vector_imports_with_production_argon2id_and_refuses_a_wrong_password` in `protocol_test_vectors_tests.rs`; vectors entries `backup` (v3), `backup_v6` and `backup_v7`. `v2_backup_encrypts_the_seed_and_leaks_no_key_material` is not annotated yet. The claim is about the file; its strength against guessing is the password through Argon2id, and both the full backup and the identity-only export refuse a weak password (Core `5101a890c`, vauchi/private#891).
- **Section**: [keys-and-cards](protocols/keys-and-cards.md)

## S14. A duress unlock shows a decoy and sends nothing that reveals it

- **Attacker**: Someone forcing the user to unlock, and watching the network.
- **Statement**: Unlocking with the duress PIN opens a decoy, and on a device with biometric unlock the lock screen is the same with or without duress: a PIN typed before the biometric pass is refused as a wrong one; anything sent afterwards has the shape of normal traffic, cover items carry the length and timestamp of the real item they stand for, and applying one changes nothing on a linked device.
- **If false**: The coercer learns from the app or the traffic that a duress code was used.
- **Status**: partial
- **Backed by**: tests `under_the_biometric_branch_a_pin_before_the_pass_is_refused_as_a_wrong_one` and `after_a_duress_session_the_lock_still_waits_for_the_pass` in `duress_lock_screen_tests.rs`, and `a_pin_before_the_biometric_pass_leaves_the_screen_a_wrong_pin_leaves` in `lock_screen_biometric_first_tests.rs`; tests `applying_a_cover_item_changes_nothing`, `a_cover_item_has_the_length_and_timestamp_of_the_item_it_stands_for` and `a_duress_session_never_journals_a_non_cover_item` in `duress_cover_device_sync_tests.rs`; Tamarin `duress_cover.spthy`, a diff model that `test:formal` verifies and falsifies under `-DCOERCER_HOLDS_RATCHET`, the design's limit (not annotated yet). Partial: lengths and timing are outside the symbolic model, and no model covers the linked-device sentence. Without the SMK the storage file shows neither whether a duress PIN exists nor whether there is duress content, only a padded size bucket (Keys and Cards F1).
- **Section**: [keys-and-cards](protocols/keys-and-cards.md)

## S15. A linked device is a full copy of the identity

- **Attacker**: Someone who photographs the link QR, or who obtains it.
- **Statement**: Linking a device transfers the identity seed; against an honest relay a photograph of the link QR alone does not give it away, while with access to the relay a photographed or leaked link QR does and lets the attacker choose which device identity joins; the QR expires after five minutes.
- **If false**: A leaked link QR gives away the whole identity; this is stated, not hidden.
- **Status**: partial
- **Backed by**: Tamarin `device_link.spthy`, lemmas `seed_secrecy`, `initiator_agreement`, `joiner_agreement`, `photographed_qr_alone_keeps_the_seed` (only under `-DHONEST_RELAY`, falsified there with `-DNO_CODE_CHECK`), and the attack lemmas `qr_leak_exposes_seed` and `qr_leak_lets_attacker_choose_joiner_identity`; Quint `device_link_machines.qnt`, invariants `joiner_seed_implies_registered` and `no_device_registered_for_a_failed_joiner`, both under a reliable relay. Partial: under a lossy relay a device whose joiner gave up can still be registered; CI asserts that violation (vauchi/private#808). Per-device subkeys that would contain a leak are planned.
- **Section**: [keys-and-cards](protocols/keys-and-cards.md)

## S16. Accepting a recovery needs the real recovery

- **Attacker**: Someone who tells your contacts you lost your phone, with the old device or not.
- **Statement**: A contact only rekeys with a recovering user whose recovery was genuinely initiated, unless both helpers it counts are corrupted, and the key it then agrees with the recovered user stays secret from the attacker.
- **If false**: An impostor takes over a contact's channel by claiming a recovery.
- **Status**: partial
- **Backed by**: Tamarin `recovery_acceptance.spthy`, lemmas `accept_needs_the_real_recovery`, `john_key_secrecy`, `alice_rekeys_only_with_an_accepting_contact` (under `-DIN_PERSON` only), and the attack lemma `a_stranger_can_rekey_with_the_recovering_user`. Partial: a contact who accepts a recovery proof does not yet receive a key bound to the recovered identity; the fix is in progress. No contact accepts a recovery automatically until the policy guardians' decision certificate exists (Social Recovery C3): against a thief holding the old device, guardian tokens and the old key's continuation move no contact (`recovery_stolen_device_tests`). The lemmas cover a single recovery (`restriction Once`), not two competing for one identity; that the guardians' decision has one outcome is a separate Quint model, not built (vauchi/private#796).
- **Section**: [social-recovery](protocols/social-recovery.md)

## S17. Social recovery needs the guardians, and only the real ones

- **Attacker**: Someone impersonating a guardian or the recovering user.
- **Statement**: Restoring from guardians needs the threshold of guardians' shares; a member of the same recovery group can stand in for an absent guardian; each side rekeys only with the real counterpart.
- **If false**: A single guardian, or an impostor, recovers someone else's identity.
- **Status**: partial
- **Backed by**: Tamarin `social_recovery.spthy`, lemmas `backup_needs_both_guardians` and `a_group_mate_can_stand_in` for the first two sentences, with the Shamir split, sealing, response and restore as Core API under test (Social Recovery A). Partial: the guardian backup ships (sent on designation, refreshed, handed back), and the restore that keeps the same identity (Social Recovery A11) is planned. The third sentence concerns compromise rotation (Social Recovery C): it is backed by `john_rekeys_only_with_the_real_alice` and `alice_rekeys_only_with_the_real_john` for a single recovery, and Core's rekey accepts nothing until the policy guardians' certificate exists (vauchi/private#796). A contact restored and waiting takes the key of an in-person exchange (Social Recovery C5); through the multi-stage modes only once the peer's identity signature verified and the peer said it saved (In-Person Exchange E8, S18).
- **Section**: [social-recovery](protocols/social-recovery.md)

## S18. A multi-stage exchange saves only the identity that signed it, after the peer accepted

- **Attacker**: Someone who controls what the cameras read, films both screens and knows the public keys of the user's contacts.
- **Statement**: Through Hover or TapHoverShake a phone saves a contact only under an identity whose holder signed that session's payload, only after the peer, in that session, accepted it, and believes the peer saved only when it did.
- **If false**: A person who knows a contact's public key replaces the card the user holds for that contact, or one phone saves a contact the other refused.
- **Status**: shipped
- **Backed by**: Tamarin `multistage_exchange.spthy`, lemmas `card_authentic`, `peer_accepted_before_save` and `peer_saved_is_true`, each falsified by its control (`-DNO_PAYLOAD_SIG`, `-DLEGACY_TAG`, `-DCONFIRM_BEFORE_VERIFY`, `-DNO_LABEL`) and kept under `-DREBIND` and `-DACCEPT_IN3D`; tests in `multistage_identity_binding_tests.rs`, `multistage_payload_tests.rs`, `multistage_final_frame_tests.rs` and `multistage_restored_rekey_tests.rs`. The untagged `FAI3` and a lost last frame are outside the statement (In-Person Exchange E, security considerations).
- **Section**: [in-person-exchange](protocols/in-person-exchange.md)

## S19. Meeting again changes a contact's key only after its person said yes

- **Attacker**: Someone who controls what the cameras read, films both screens and knows the public keys of the user's contacts.
- **Statement**: Through Hover, a phone that already holds a contact and meets that identity again gives the contact a new key only after its own person agreed, and only the key of a session that contact's identity opened. It asks only when the peer itself stated that it no longer holds this phone. The phone that lost the contact saves it again only after that yes.
- **If false**: A bystander makes a phone replace a working connection with a key the contact does not hold, or makes the question appear when the contact lost nothing.
- **Status**: shipped
- **Backed by**: Tamarin `multistage_exchange.spthy`, lemmas `a_key_changes_only_after_a_yes`, `a_rekey_is_with_the_contacts_own_session`, `the_question_follows_the_peers_own_statement` and `a_waiting_phone_saves_only_after_the_holders_yes`, each falsified by its control (`-DREKEY_WITHOUT_ASKING`, `-DNO_PAYLOAD_SIG`, `-DSTATEMENT_IN_CLEAR`, `-DDONE_LABELS_SHARED`) and kept under `-DREBIND`, with `a_reconnect_is_possible` showing the path exists; tests in `multistage_holding_statement_tests.rs` and `repeat_exchange_reconnect_tests.rs` (vauchi-core) and `multi_stage_reconnect_tests.rs` (vauchi-app). The model assumes that a person says yes only for the contact who is with them; it does not prove that about people. Whether a phone's own statement is true is outside the statement, as are Glance and Link, where a repeat exchange changes no key.
- **Section**: [in-person-exchange](protocols/in-person-exchange.md)

## Notice core (proposed)

The goal these claims serve (ADR-081): Vauchi's relays cannot
reconstruct who is in touch with whom, against the application relay
alone and with the OHTTP relay, at every growth stage. The claims below
cover the key delivery of one cohort; the other stages are in ADR-081's
growth plan, not claimed here.

These are reviewed claims about a proposed design, the
[Notice Core](protocols/notice-core.md) of mailbox cohorts (ADR-081),
not shipped properties: the design is implemented in Core behind the
`notice-core` feature and wired to nothing, so no user has them today.
They keep the labels of that chapter (P2, P3, P5, P6) and take no
S-number until they ship. Each holds only within the windows and
conditions it states. The attackers are those of the chapter's section
B, also listed in [Attackers](attackers.md): G, the gateway without
keys, and T, a copy of a device's state taken once. The design these
claims describe is Core `3af62982a`, which passed the project's review
and reached `main` as `adfb1f7d8` with the same notice code;
a human cryptographer reviews it before release. Core's conformance
schedules ([Test Vectors](vectors.md#notice-core-proposed)) check that
Core decides what an independent implementation of the protocol text
decides; that is agreement with the text, not a proof of these claims.

### P2. A later copy of a device reads no superseded update

- **Attacker**: T: someone who copies the full state of the sender S or
  the receiver R once, later, and reads what the relays still keep (120
  days).
- **Statement**: Each update has its own key, and outside the windows
  below a later copy of either device reads no superseded update from
  the relays.
- **Windows**: S deletes an update key when a newer update supersedes
  it, from its queues too. R deletes a notice's key once it has read
  the notice; keeps an update key at most 21 days after the last notice
  that carried it while it waits for the content (each view renews it);
  keeps the key of a position it skipped for three refresh periods from
  the skip; and keeps the means to read an epoch's notices for three
  refresh periods after leaving it. These windows add up: an update key
  read late from a skipped position, an epoch left, or a position of
  the current epoch not read yet can then wait 21 days as pending, so a
  later copy may hold a superseded key for both windows together; the
  last case lasts while R stays in the epoch. A notice R has not yet
  read in its current epoch stays readable to a later copy of R until R
  moves on and three periods pass.
- **Conditions**: every window runs on the device's clock and is closed
  in the device's sessions. A clock set back lengthens it by up to the
  set-back, and once corrected may end it up to that much early. A
  device that runs no session keeps what it holds until its next one,
  up to the relays' 120 days; a copy taken from storage while the app
  has not run holds the keys whose windows ended since its last
  session. The windows cover saved state and the protocol's live state,
  not leftovers in freed memory: the HKDF and HMAC crates Core uses
  (0.12) do not wipe their internal state, so a copy of the process's
  memory may still hold key material this claim calls gone.
- **If false**: Someone who copies a phone later opens card updates that
  its contacts have since replaced.
- **Status**: proposed; reviewed, not shipped.
- **Section**: [notice-core](protocols/notice-core.md), B (P2), C (B1,
  B2) and 4.

### P3. A copy that only reads stops reading new updates

- **Attacker**: T, a copy of S or of R that reads the cohort and writes
  nothing.
- **Statement**: The copy loses access to updates made afterwards once
  R has made a refresh after the copy, S has opened it, R has named the
  new epoch and S has followed that name.
- **Windows**: up to about four refresh periods: up to about 23 days
  with sessions every three days, and about 27 when R's clock runs
  three days ahead at each refresh and is corrected after.
- **Conditions**: both devices have sessions and S's slot budget is not
  full. While R makes no refresh, nothing heals. A copy of S still
  recognises the weekly publications of a body it already holds until
  the group is next edited; it learns nothing from them except that no
  edit happened. If an older refresh reaches S after a newer one, S
  writes in the older epoch until the next refresh; within one session
  S avoids that by order, so it takes the gateway, and a copy the
  gateway helps is not defended.
- **If false**: Someone who copied a phone once keeps reading its
  contacts' new cards.
- **Status**: proposed; reviewed, not shipped.
- **Section**: [notice-core](protocols/notice-core.md), B (P3), C (R1,
  R2, S4) and 7.

### P5. The relays without keys cause no alarm and no lasting loss

- **Attacker**: G, the outer relay and the application relay colluding,
  holding no device keys: it drops, delays, reorders and replays
  records, injects or alters bytes, and withholds acknowledgements.
- **Statement**: Honest use and G alone raise no alarm, and cannot stop
  R converging on S's latest card once G delivers again.
- **Windows**: those of the chapter's P1: with nothing lost, within two
  sessions of each device; after a lost notice, within one refresh
  period plus two sessions of each device; after lost content, within
  two refresh periods; after a lost notice and lost content together,
  within about three. Where the notice or content budget is full,
  records queue and the card arrives later.
- **Conditions**: the devices' clocks stay within the chapter's bounds:
  up to three days apart, sessions at least every three days, an
  absence of at most 14 days. A device whose clock is wrong by more
  than a week receives nothing new until it is right. A clock set back
  by months, together with a gateway that kept honest records far
  beyond the relays' 120 days, can raise one alarm with no key: the
  sender has forgotten the refresh and the epoch it named.
- **If false**: The relays alone, without any key, make a user see an
  alarm about a contact, or keep an old card for good.
- **Status**: proposed; reviewed, not shipped.
- **Section**: [notice-core](protocols/notice-core.md), A, B (P1, P5)
  and 6.

### P6. Every device writes the same, so the relays learn no direction

- **Attacker**: G, which watches every write and read, and delays,
  drops and replays records.
- **Statement**: G cannot tell a control record from an update notice
  or a dummy, link a direction's records, or learn who writes to whom
  within a cohort: every device writes exactly 80 notice slots of 96
  bytes and 5 content slots of 576 bytes a background session, and 40
  and 2 an open-app tick, whatever it has to send, with random bytes in
  every unused slot and the slots in a random order, and every member
  downloads every slot of its cohort.
- **Conditions**: P6 is argued for a gateway that watches, delays,
  drops and replays; it is not analysed against one that adapts its
  tampering to what it observes. It does not hide which devices
  registered in a cohort or when each wrote ([Relay](protocols/relay.md)
  A11). In the alpha and beta every device is in the one cohort;
  routing between cohorts is release work.
- **If false**: The relays learn who keeps whose card, and when a
  contact edits theirs.
- **Status**: proposed; reviewed, not shipped.
- **Section**: [notice-core](protocols/notice-core.md), A, B (P6) and
  8.

### Not claimed: a copy that writes

Against a copy that writes records, the notice core promises best
effort only (its P4): the alarms of the chapter's section D are raised
when a device sees their condition, and there is no promise that such a
copy is always alarmed or that its hold on the direction always ends.
Known limits, each of which needs the copy to write:

- A copy of S that writes every chain position first, and answers R's
  refreshes itself, can hold the direction for as long as it writes;
  after R alarms inside an epoch only the copy holds, the refresh copies
  R seals there after an alarm no longer reach S.
- A refresh a copy seals under a new number, with its own key and a
  name it reads, moves S's writing epoch there. R alarms when it reads
  the opening only if the number is one R watches (its own and the two
  above its newest); a higher number R does not see at all.
- A copy that keeps forging one higher-numbered refresh a week keeps the
  receiver's own refreshes from opening: while the opening on that
  higher number is queued, R's refreshes are read as handled and open
  nothing, and are not opened later. Healing never starts for as long
  as the copy writes, with no alarm; it starts once the copy stops.
  While the copy writes, only re-verifying the contact in person ends
  it.
- A copy of R can open the refreshes R issued while S was away, and R
  moves into the copy's epochs; R's later refreshes reach S only if R
  saw something that alarmed.
- A copy of S that writes at a notice-chain position before S does is
  read, and S's record there is not, until the weekly current view
  replaces it.
- A copy can spend S's resources: each refresh it seals costs S a proof
  search and an opening, more than 12 unanswered ones push out the
  epochs with the lowest numbers, a copy of S's notices can push out
  R's pending update keys (32 a direction), and what S's bounded table
  of refreshes forgets is no longer checked.
- A copy of R that seals a refresh under a very high number, and then
  names the epoch S opens on it, makes every epoch below that number
  last three periods only, also after the copy stops.
- A copy of S that writes far ahead on a notice chain makes R give up
  the positions S really uses until the direction moves to a new epoch.
- An alarm depends on a record being read; if that record is lost,
  nothing is raised.

A copy of S also holds S's identity key and can sign cards as S at any
version; that is impersonation through a stolen identity key, with or
without cohorts, and outside the notice core.

## Not claimed

Limits known today, so that a reviewer does not spend a week proving them:

- The relay sees metadata: which mailbox tokens receive how much, and when. Sealed sender and padding reduce it; they do not remove it. Mailbox cohorts, in which every member downloads its cohort's whole batch and every device writes a fixed number of same-sized records on a fixed schedule, are proposed and not in the app (ADR-081; their key delivery is the [Notice Core](protocols/notice-core.md), whose claims are above); they would hide who writes to whom within a cohort, not cohort membership or when a device is online.
- The relay can correlate one fetcher's per-day requests by their timing on the immediate path; the delayed path spreads it. Until core!2060 (merged 2026-10-28) the requests also overlapped in yesterday's tokens across days, which made the fetcher a stable pseudonym (S4).
- Three relay routes are addressed by an identity key or its hash: guardian sets, recovery proofs and purge. A recovery is visible metadata to the relay by design.
- Token unlinkability is not forward secure: a mailbox token is a deterministic function of the channel's shared key, the recipient's key and the day, so whoever later obtains a contact's shared key can recompute every past token of that channel and link them in a retained log (S4).
- Device-to-device sync has no forward secrecy: a later compromise of a device's exchange key opens every recorded batch, and batches carry contacts, cards and shared contact keys (S11). Live pairwise ratchet states are not copied.
- Backup confidentiality against offline guessing depends on password strength and Argon2id. Both full backups and identity-only exports reject weak passwords; this does not make an accepted password immune to guessing (S13).
- A duress PIN is six digits. Someone who images the device and also holds the SMK opens its seal, learns whether a duress PIN exists, and brute-forces the Argon2id hash offline in about a million guesses; duress protects against a coercer who watches, not one who extracts the storage and the keychain, and the latter already holds the data (Keys and Cards F). Without the SMK the storage file does not show whether a PIN exists or whether there is duress content; one sealed row holds all of it, and its size bucket (4 KB, then doubling) is what remains readable.
- A compromised device exposes the whole identity seed. Subkeys are planned.
- There is no key transparency log. A relay that hands out a wrong key for a first contact is not auditable today; a signed log is planned.
- The key agreement is not post-quantum. Recorded ciphertext could be read by a future quantum computer; a hybrid ML-KEM scheme is planned.
- No external cryptographic audit has been performed. It is planned and depends on funding.
