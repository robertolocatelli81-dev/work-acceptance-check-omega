# war-verify: a clean-room verifier for work-acceptance records (profile 1.4.2)

`war_verify.py` checks a work-acceptance record (Trilatic draft profile 1.4.2 at
maximusrufus/work-acceptance-record@85a310d, vectors 01-87, schema identifier `trilatic.acceptance-receipt/1.2`, unchanged since
1.2.1) the way the profile README describes, and refuses anything it does not understand. Version 0.6.0 follows the
1.4.2 rules (see "Profile 1.4.2 rules") and the clarification of 2026-10-27 (cb7e8f1, vectors 88-90, read on
2026-10-28); the 1.4.1 sets (bc5a138, 48ab8c9, 06d3b94) still agree in full. The readings this
verifier gave to profile 1.2.1 (version 0.1.0) are kept: `--profile 1.2.1` selects all of them, and each one has
its own switch (see "Switches"). It was written from the profile README, the published test vectors and the RFCs it
names. No other implementation was opened, with these exceptions (see "What was read"): an issue comment that quotes
parts of the reference verifier was read before version 0.4.0, and the description of a probe vector before 0.4.1;
for 0.5.0 the payment form was taken from the function `_in_form` of the reference `verifier/check_payment.py`
(opened), and the reference `verifier/war_verify.py` of bc5a138 was searched once with `grep` and run as a black box
on this project's own probe documents. For 0.6.0, `verifier/`, `interop/` and `composition/` of 85a310d were not
opened.

Licence of this project's own files: MIT OR Apache-2.0 (`LICENSE-MIT`,
`LICENSE-APACHE`). The new vectors in `vectors/` are CC0, like the upstream vectors.

Third-party inputs are **not included** in this repository. `python3 tools/fetch_sources.py` downloads them from the
commits and URLs pinned in `SOURCES.json` into `fonti/` and `roots/`, and keeps a file only if its SHA-256 matches;
the tests need them. Their licences are their authors': the profile README is CC BY 4.0
(maximusrufus/work-acceptance-record), the upstream vectors (88-90 at cb7e8f1; 01-87 at 85a310d; 01-59 at 48ab8c9, then the head of PR #1, merged on
2026-10-27; 01-57 at bc5a138; 01-47 at 06d3b94, 01-46 at 4daf721, 01-36 at eb0f30b, 01-27 at 42b4ed0) and the Tetsurohhori vectors carry
CC0-1.0, and the babyblueviper1
vectors and the issuer files (`selftest-pass.json`, its README, `checker-keys-live.json`) state no licence. The
issuer's key file is fetched from its live URL, so it can change: the script then reports a mismatch and does not
use it.

## What it checks

Profile steps 1-9, with the problem and warning codes of step 8:

1. schema, canonicalization and suite are the ones of the profile, otherwise refusal with the outcome
   `{"refused": true, "reason": "unknown schema, canonicalization or suite"}`;
2. RFC 8785 canonical form of `receipt` (own implementation, tested on RFC 8785 Appendix B), Ed25519 signature with
   the key named by the signed `receipt.key_id`. An envelope `signature.key_id` that differs is `SIGNATURE_INVALID`.
   Key rule: if the key named by `receipt.key_id` is not a canonical encoding of a point of prime order, the
   record is `KEY_REJECTED` and no signature check runs (another bad entry in the key file gives the local block
   `X_UNUSED_KEY_REJECTED`, see `--key-rule`);
3. delivered and original files, when supplied (`delivered_file_base64`, `original_file_base64`);
4. criteria document hash, and that the results correspond to the criteria;
5. criteria commitment: imprint of the criteria token (SHA-256 by OID), its genTime against `committed_at`,
   fallback to `committed_at` with `CRITERIA_COMMITMENT_UNVERIFIED`, strict "earlier than" against the reference
   time, which is the earlier of `issued_utc` and a covering record token's genTime. A token's stated `accuracy`
   widens the comparison, a token without one is taken at its genTime, and `ordering` is ignored. From 0.6.0
   (1.4.2): times to the millisecond (criteria up, reference down), a `genTime` outside DER UTC form gives no time,
   and a stated time outside `YYYY-MM-DDTHH:MM:SS[.fff]Z` is `RECEIPT_TIME_UNREADABLE` (R4, R5);
6. record token imprint (`none` / `imprint_match` / `imprint_mismatch`); the unsigned envelope `timestamp` never
   decides it. Profile step 6: "the unsigned `timestamp.digest_sha256` field is informative and never decides the
   outcome": from 0.5.0 a `digest_sha256` outside its form (not a string of 64 lower-case hexadecimal digits) is the
   local code `X_TIMESTAMP_METADATA_MALFORMED` and a note, not a refusal (0.4.1 refused it). The other members of the
   envelope timestamp are not named by the profile and keep the issuer's form, as before (refused outside it; an
   unknown member is a note under `--unknown-fields report`);
7. verdict recomputed from the results;
8. independence: checker is the signer (by the signed `key_id`, R7), key collision (keys compared as decoded bytes),
   self-check label, producer declared, a stated party `key_id` that is empty, unlisted, repeated or not canonical
   (derived `self-checked`, R6), and the stated `independence` against the one derived from the parties block;
9. time-stamp authority signature (profile 1.4.1): with relying-party anchors (`inputs.tsa_roots_base64` in the
   vectors, or `--tsa-roots`), `tsa_signature` has one key per token present (`criteria`, `receipt`) with the value
   `verified`, `failed`, `untrusted`, `unsupported` or `no_signer`; without anchors `not_evaluated`. It never changes
   another member. `--tokens pkix` in addition stops using the time of a token that is not `verified`
   (`details.token_authentication`, a local choice, see "Switches").

How the values are assigned:
- `no_signer`: no SignerInfo, or no certificate in the token matches the SignerInfo's `sid` (certReq=false);
- `unsupported`: a TSA key or signature algorithm outside the closed list this verifier implements, which is the
  profile's required set: RSA PKCS#1 v1.5 and ECDSA on P-256 or P-384. RSASSA-PSS (optional in 1.4.1), other curves
  (P-521 included), Ed25519 and other key types are `unsupported`; so is a digest algorithm outside SHA-1/SHA-2. The
  key algorithm is read from the signer certificate's SubjectPublicKeyInfo by this verifier's own DER parser
  (`rsaEncryption`, `id-ecPublicKey`), so an unknown one is `unsupported` on every `cryptography` version, before the
  engine loads the key; a key under a listed algorithm that the engine cannot load is `failed`;
- `failed`: anything else about the token itself: content-type or message-digest attribute, the signature over the
  signed attributes, the ESS signing-certificate binding, EKU (`id-kp-timeStamping` only, critical, RFC 3161 2.3),
  `TSTInfo.tsa` naming another subject, the signer certificate outside its validity at genTime, more than one
  SignerInfo;
- chain: a chain of CA certificates (each signature verified, basicConstraints CA, keyUsage keyCertSign when
  present, and every issuer other than the anchor valid at genTime) must reach a supplied anchor. An issuer that
  fails one of these checks gives `failed` whether or not the chain reaches a supplied anchor (bc5a138 step 9,
  vectors 38 and 54; until 0.4.1, `untrusted` when it did not). No path to a supplied anchor is `untrusted`. The anchor's own validity period is not checked;
  the signer's is, even when the signer certificate is itself supplied as the anchor. A root carried in the token
  is used only if the same certificate is supplied as an anchor. The anchor is reached by subject name and public
  key (1.4.1 at d79a737: "matched by subject name and public key, RFC 5280 6.1.1, not by certificate bytes"): the
  supplied anchors are issuer candidates in the walk and the walk stops at the first of them, so a cross-signed copy
  of the anchor inside the token reaches it, and a certificate with the anchor's name but another key does not
  (`tests/test_nemesis_141b.py`).
- A certificate carried in the token whose DER or extensions do not parse (for example a duplicate extension) is
  not used: `failed`, and when it was the one named by the SignerInfo also `no_signer`. An anchor like that is
  refused in `inputs.tsa_roots_base64` and skipped by `--tsa-roots` (exit 74 when nothing readable is left). A
  `TSTInfo.tsa` that is not a directoryName holding a Name is `failed`.
- When one token has defects of several classes, the value is `failed` if any check that can run fails, otherwise
  `no_signer`, then `unsupported`, then `untrusted` (profile 1.4.1; `--tsa-precedence failed-first`, the default).
  `evaluability-first` (`no_signer`, then `unsupported`, before `failed`) is the order another verifier reported for
  1.4; it is kept for comparison and disagrees with vectors 44-46 by construction.
- An empty `tsa_roots_base64` array is "without relying-party anchors": `not_evaluated`, with a note (1.4.1, 43).
- Vector member `tsa_signature_accepted` (1.4.1, vector 40): per token, further values that also conform. Closed
  grammar (keys `criteria`/`receipt`, each a non-empty array of distinct step-9 values), otherwise refusal.

The output has the nine fields of the vectors' `expected` objects, plus `accepted_as_stated`, `extension_codes`
(this verifier's own observations, prefixed `X_`, never mixed with the profile's codes), `notes` and `details`.

## What it does not check

- Without anchors it does not verify the time-stamp authority's signature (profile 1.4.1 step 9: `not_evaluated`).
  The tokens of vectors 01-30 are "imprint-and-time fixtures" with no SignerInfo: with anchors they read `no_signer`.
- Revocation of TSA or CA certificates: no CRL or OCSP is fetched (profile 1.4.1: "Revocation is not checked").
- The optional `receipt.payment` member against a chain: it is covered by the signature like the rest of the body,
  but no settlement is looked up (the profile makes it outcome-neutral). Its form is the one bc5a138 states (README and
  `verifier/check_payment.py`): exactly `protocol`, `scheme`, `network`, `asset`, `payer`, `pay_to`, `amount`,
  `nonce` and optionally `settlement_tx`, all strings; `protocol` `x402`, `scheme` `exact`; `network` `eip155:` and a
  decimal chain id without leading zeros, 1 to 32 digits; `amount` a decimal string without leading zeros; `asset`,
  `payer` and `pay_to` 20 bytes, `nonce` and `settlement_tx` 32 bytes, each `0x` and hexadecimal digits of either
  case. "A member outside it changes no outcome" (vector 55): from 0.5.0 a payment outside the form is a note naming
  the defect and `unsupported`, not a refusal (0.4.1 refused it); one inside the form is a note too. The rules for the
  whole document still apply inside `payment`: an integer outside plus or minus (2^53 - 1), for example an `amount`
  of 1000000000000000000 written as a JSON number, refuses the record (see "Closed by construction"), although
  RFC 8785 3.1 only asks that a number be expressible as an IEEE 754 double.
- OpenTimestamps proofs. The issuer README says its criteria commitment comes with an OpenTimestamps proof, but
  `selftest-pass.json` contains no OpenTimestamps data, so there was nothing to check.
- Whether a criterion was judged correctly. A record states a checker's findings; this tool checks the record.

## Closed by construction

Every member of every object is either understood or the input is refused with a reason naming the path, with the
exceptions the profile itself fixes, each listed in `notes` and never ignored silently: the members
`numbers_for_canonicalization` (bc5a138 vectors 52 and 57), `numbers_exponent_form` (85a310d vector 84) and
`keys_utf16_order` (85a310d vector 85) of `receipt.tools` (any other member of `receipt.tools` is an unknown member),
a `receipt.payment` outside its form (vector 55), a `digest_sha256` outside its form in the unsigned envelope
`timestamp` (step 6), a `statusString` whose `UTF8String` holds bytes that are not UTF-8 (vectors 50 and 51), and the
1.4.2 cases that are outcomes, not refusals (non-canonical base64 in a signature, a key entry, a token or a supplied
file; an upper-case digest; a token `genTime` that is no usable time; a stated time in another form; a repeated
`key_id`: see "Profile 1.4.2 rules"). A member of another type than the specification gives is refused with the step
1 outcome (1.4.2 R8). That includes duplicate JSON member names, lone surrogates, integers outside the I-JSON range of plus or minus
(2^53 - 1), a byte order mark, base64 that is not canonical in `tsa_roots_base64`, any non-DER encoding in a token
(a `genTime` element not tagged GeneralizedTime included), and, under `--ed25519 strict`,
a signature whose R is not canonical or is of small order. An Ed25519 public key in the key file that is not
canonical or not of prime order is not refused: as the signer's key it is `KEY_REJECTED` (profile 1.3 step 2), as
any other entry it is the local block `X_UNUSED_KEY_REJECTED`. Under `--profile 1.2.1` the input is refused, as in
version 0.1.0.

Where a standard says what to do with an unknown element, that rule is followed and listed in `notes`: a
non-critical TSTInfo extension is ignored (RFC 5280 4.2), a critical one is refused, and an unknown PKIStatus is an
error (RFC 3161 2.4.2). The imprint, `genTime` and `accuracy` are read from the signed `TSTInfo` only, "never other
bytes of the response, such as `PKIStatusInfo.statusString`" (bc5a138 step 5). A `statusString` whose `UTF8String`
holds bytes that are not UTF-8 (the layout of vectors 50 and 51) is listed in `notes` and not read (0.4.1 refused the
response; `tests/test_status_info.py`), so an imprint copied there in the unsigned `statusString` of a genuine token
gives `CRITERIA_TIMESTAMP_MISMATCH` for the criteria token and `imprint_mismatch` for the record token, as vectors 50
and 51 expect. Anything else outside `PKIFreeText` (RFC 4210 5.1.1: an empty sequence, a member that is not a
`UTF8String`, a member that is not DER, an element of `PKIStatusInfo` other than one `statusString` sequence and one
`failInfo` in that order) is refused like any other DER defect of the response: no vector or sentence of the profile
fixes it (0.4.0 accepted any sequence silently). A `failInfo` must still be a DER `BIT STRING`
(unused bits zero and, as `PKIFailureInfo` is a named bit list, no trailing zero bits, X.690 11.2), else refusal: no
vector or sentence of the profile says otherwise.

The profile does not define the envelope, key-file or criteria-document formats. The member sets accepted for
them are those found in the published inputs (the 26 documents of the 1.2.1 round and the 27 vectors of 1.3). For the criteria document, only `criteria[].id`, `required` and
`title` are interpreted, and the other members are listed in `notes`. `--unknown-fields report` turns refusals
for unknown members into notes (the four exceptions above are notes under both values).

## Profile 1.4.2 rules (85a310d, vectors 58-87; version 0.6.0)

Profile 1.4.2 (maximusrufus/work-acceptance-record@85a310d, README step 10 "Profile 1.4.2 rules" and its changelog
entry of 2026-10-27) is the default from 0.6.0. Each rule below is written from that text and the vectors named; the
number after each rule is the vector that fixes it. Where the text leaves a case open, the reading taken here is
marked **reading** and listed in "Readings not fixed by the vectors" as a question for the profile author.

- **R1 canonical base64** (60-63, 69). A base64 value is canonical when it uses the standard alphabet, `=` padding to
  a multiple of four, no whitespace, and re-encoding the decoded bytes gives the same string (RFC 4648 4).
  - `signature.value` not canonical: `SIGNATURE_INVALID`, `signature_valid` false, no signature check; the other
    outcome members are still computed (60-63). A value that is not a string is a type error (R8).
  - a key-file `public_key_base64` not canonical: that entry is a rejected key and the problem `KEY_REJECTED` is
    raised. As the signer's key, no signature check runs; as the producer's or checker's, independence is derived
    `self-checked` and the entry is not compared with any other key (69). **Reading:** an entry named by no party
    and not the signer's also gives `KEY_REJECTED` (the R1 sentence "a non-canonical public key is `KEY_REJECTED`"
    has no restriction, unlike the step 2 point rule; no vector).
  - `criteria_file_base64` not canonical: it matches nothing, `criteria_hash` `mismatch` and
    `CRITERIA_HASH_MISMATCH` (cb7e8f1 vector 89). `criteria_tsr_base64` not canonical: a token over other bytes,
    `CRITERIA_TIMESTAMP_MISMATCH` and the fallback with `CRITERIA_COMMITMENT_UNVERIFIED` (first a **reading**, then
    cb7e8f1 vector 90); `tsa_signature.criteria` is `not_evaluated` without anchors and `failed` with them: the token
    is not decoded (the profile author's answer on x402-foundation/tsc#4, comment 6460276466 of 2026-10-28, not in
    the profile text, Q3; as first written for 85a310d the member was absent). `receipt_tsr_base64` not canonical:
    `imprint_mismatch`, and `tsa_signature.receipt` takes the same values: the answer names the criteria token, and
    "as for any malformed token" is read here as covering the record token too (**reading**). Delivered and
    original files: `mismatch` (local codes, as for a hash mismatch). `tsa_roots_base64` is not named by R1 and stays
    refused when not canonical (closed by construction). Each case is listed in `notes` (`X_BASE64_NONCANONICAL`).
- **R2 lower-case digests** (67). `criteria.sha256`, `files.*.sha256`: a string of 64 hexadecimal digits in which
  any digit is upper case matches no digest (not lower-cased): `criteria_hash` `mismatch`, and the criteria token
  over the lower-case value is `CRITERIA_TIMESTAMP_MISMATCH`. Any other string (wrong length, not hexadecimal) is
  still refused: the profile names upper case only (**reading**).
- **R3 repeated key identifier** (75, 79). A `key_id` listed more than once in the key list is `KEY_REJECTED`,
  whichever entry comes first and wherever it is (79: neither party's, signature still valid). As the signer's
  identifier no signature check runs (`signature_valid` false, 75); as a party's identifier independence is derived
  `self-checked`. Under `--key-rule refuse` (`--profile 1.2.1`) the input is refused, as before.
- **R4 form of `genTime`** (66, 68, 70-74, 78). A token `genTime` is usable only as DER GeneralizedTime in UTC:
  `YYYYMMDDHHMMSS`, optionally `.` and digits whose last is not `0`, then `Z`, with real calendar fields (second 60
  is not accepted: **reading**). Any other content is no usable time: the token gives no time, the criteria side falls
  back to `committed_at` with `CRITERIA_COMMITMENT_UNVERIFIED` and raises no problem when the imprint matches (78);
  the imprint is still checked (a mismatch is still `CRITERIA_TIMESTAMP_MISMATCH`). On the record side
  `receipt_timestamp` still reports the imprint, but the token is not a reference time (**reading**). Note
  `X_GENTIME_UNUSABLE`. A `genTime` element that is not tagged GeneralizedTime is a DER defect and stays refused.
  Until 0.5.0 every such token was refused. With anchors, the authority check of such a token cannot check validity
  at genTime and is `failed` (**reading**).
  - millisecond rule (66, 68): for "committed before", the criteria time is rounded **up** to the millisecond and the
    reference time **down**, then compared with a strict `<`. A stated `accuracy` is added after rounding
    (**reading**: the text does not order rounding and widening). `CRITERIA_TIME_MISMATCH` keeps its 1.2.1 rule
    (the token time truncated to `committed_at`'s own precision; 66 states "compared to the second").
- **R5 stated times** (76). `committed_at` and `issued_utc` must be `YYYY-MM-DDTHH:MM:SS[.fff]Z` with real calendar
  fields; **reading:** `.fff` is exactly three digits. A string in another form is no longer refused: it gives the new
  problem code `RECEIPT_TIME_UNREADABLE` and `criteria_committed_before_check` `no`, never
  `CRITERIA_COMMITTED_AFTER_CHECK`. `issued_utc` is always used by step 5; `committed_at` only when no usable
  criteria token supplies the time; with one, a `committed_at` in another form is `CRITERIA_TIME_MISMATCH` and the
  token decides "committed before" (cb7e8f1 vector 88, clarification of 2026-10-27; as first written for 85a310d,
  0.6.0 read it as `RECEIPT_TIME_UNREADABLE` also then, Q6). A value that is not a string is a type error (R8).
- **R6 independence by key** (65, 69, 80-82, 87). Keys are compared as decoded bytes: two identifiers whose entries
  decode to one public key are one key, `KEY_COLLISION` and derived `self-checked` (65, 87; already so in 0.5.0). A
  party's `key_id` that is stated (present and not null) must be non-empty and listed exactly once with a canonical
  entry, else independence is derived `self-checked`, and a stated `independent` is `INDEPENDENCE_INCONSISTENT` (80,
  81). An empty or unlisted identifier raises no other code of this rule (as the checker's it is still
  `CHECKER_NOT_SIGNER`, Q14); a repeated or non-canonical one is also `KEY_REJECTED` (R1, R3). A party's `key_id` may now be absent (82): absent and null both mean "not stated", and the producer then
  rests on the party names.
- **R7 checker is the signer** (64, 86). `CHECKER_NOT_SIGNER` compares `parties.checker.key_id` with the signed
  `receipt.key_id` as identifiers; the envelope `signature.key_id` never enters it. Until 0.5.0 the comparison was by
  public key (an identifier for the same key as the signer did not raise it); the envelope rule of step 2
  (`SIGNATURE_INVALID`) is unchanged. Under `--key-id-source envelope` (`--profile 1.2.1`) the 0.5.0 comparison is kept.
- **R8 types** (77). A member of the record or of the inputs whose type is not the one the specification gives
  (object, array, string, integer, boolean) is refused with the step 1 outcome
  `{"refused": true, "reason": "unknown schema, canonicalization or suite"}`; the path is in `reason_detail`. Other
  refusals (missing or unknown members, values outside a stated set, non-DER tokens) keep their own reason.
  **Reading:** the unsigned envelope `timestamp.digest_sha256` keeps the 0.5.0 rule even when its type is wrong (a
  note, `X_TIMESTAMP_METADATA_MALFORMED`): step 6 says it "never decides the outcome", and R8 does not say which of
  the two wins. The same holds for `receipt.payment`: the member itself, or any of its members, of another type is a
  note and `unsupported` (bc5a138 vector 55, "a member outside it changes no outcome"), not a refusal (Q13). The
  members of the envelope `timestamp` (`status`, `covers`, ...) are checked for type like the rest.
- **R9 unsigned attributes** (83). `unsignedAttrs` of a token's SignerInfo are not read and are no ground for refusal
  (already so in 0.5.0: the `[1]` member after the signature is skipped).
- **R10 vectors 84 and 85** (RFC 8785 exponent numbers, a member name outside the Basic Multilingual Plane) needed
  no change of the canonicalization. They carry two new members of `receipt.tools` whose outcome the vectors fix (no
  problems): `numbers_exponent_form`, an array of numbers (84), and `keys_utf16_order`, an object whose values are
  strings (85). As for `numbers_for_canonicalization` (52, 57) each is listed in `notes` and not interpreted; any
  other member of `receipt.tools` is still an unknown member. The vector member `test_key_seeds` (84-87) is read as
  vector metadata, not as an input.

## Usage

```
python3 war_verify.py RECORD_OR_VECTOR.json             # exit 0 only with every guard below, 1 otherwise, 2 refused
python3 war_verify.py --vector VECTOR.json              # compare with "expected": exit 0 agree, 3 disagree
python3 war_verify.py --keys fonti/issuer_274159c/checker-keys-live.json --tokens pkix \
        --tsa-roots roots/freetsa_cacert.pem fonti/issuer_274159c/selftest-pass.json      # exit 0 (measured)
```

Exit 0 is stricter than "accepted as stated". It requires all of the following:
- `accepted_as_stated` is true (signature valid, no problem code, commitment order decided);
- the key file came from `--keys`, not from the record's own `inputs.keys`;
- the signing key is not a `status: test` key;
- every time-stamp token whose genTime was used was authenticated with `--tokens pkix`;
- supplied files match the record;
- no key in the key file is rejected by the key rule (`X_UNUSED_KEY_REJECTED`: a bad entry that signs nothing);
- `receipt.key_id` equals `signature.key_id` (under 1.3 a difference is already `SIGNATURE_INVALID`; under
  `--key-id-agreement require`, the 1.2.1 reading, it is only this local block; `--key-id-agreement ignore` drops
  this condition).

Each condition that is not met is listed in `local_blocks` and gives exit 1. The profile fields are unchanged by
these guards, so `--vector` scoring is the profile's. Measured on 2026-10-18 (42b4ed0): vector 01 gives exit 1 with
`local_blocks` `X_KEY_FROM_INPUT`, `X_TEST_KEY` and `X_TSA_NOT_VERIFIED`. The live record gives exit 0 only with
the live key file and `--tokens pkix`.

The report also says where the key came from (`details.key_source`), the signer key's status
(`details.signer_key_status`), and whether each token was authenticated (`details.token_authentication`).
`--keys ""`, repeated options, and `--tokens pkix` without `--tsa-roots` are usage errors (exit 64). `--tsa-roots`
alone (version 0.3.0) supplies the anchors for `tsa_signature`; it then replaces the vector's
`inputs.tsa_roots_base64`, with a note.

Exit 64 is a usage error. Exit 74 means a check could not run, for example `cryptography` is not importable or
`--tsa-roots` holds no certificate. Every check that can run still runs. The report lists the others in
`cannot_run`, sets `signature_valid` to `null` when the signature could not be checked, and never sets
`accepted_as_stated` to true. Measured with `cryptography` made unimportable (`tests/test_cli.py`): vector 02 gives
exit 74, `signature_valid` `null`, `accepted_as_stated` false. Dependencies: Python 3.9 or newer and
`cryptography`; the TSA checks need `cryptography` 40.0 or newer (`Certificate.verify_directly_issued_by`). With an
older version they are a check that cannot run (exit 74, `tsa_signature` `not_evaluated`), not a result. Measured
before this guard with 39.0.2: the chain step failed silently and 31, 32 and 34 read `untrusted` (34/37). The
`cryptography` package is the Ed25519 arithmetic engine and the X.509 parser for the TSA checks.
Canonicalisation and the DER, CMS and TSTInfo parsers are written here.

## Switches: profile 1.4.2 by default, the 1.2.1 readings kept

Defaults follow profile 1.4.2 (its steps 1-8 are those of 1.3, with the step 10 rules of 1.4.2). The 1.4.2 rules have
no switch of their own: under `--key-rule refuse` a repeated or non-canonical key entry is refused as before, and
under `--key-id-source envelope` `CHECKER_NOT_SIGNER` keeps the 0.5.0 comparison by key (README, R7). `--profile 1.2.1` selects every reading this verifier gave to 1.2.1 (the rows marked
"1.2.1"); a switch given explicitly overrides it.

| switch | default | alternative | sentence |
|---|---|---|---|
| `--key-id-source` | `receipt`: the signed `receipt.key_id` names the key | `envelope` (1.2.1) | 1.3 step 2 "verify the Ed25519 signature with the key named by the signed `receipt.key_id`" |
| `--key-id-agreement` | `signature-invalid` | `require` (1.2.1: profile fields unchanged, a local block), `ignore` | 1.3 step 2 "The envelope's `signature.key_id` must equal it, else `SIGNATURE_INVALID`" |
| `--key-rule` | `signer`: the key named by `receipt.key_id`; another bad entry is the local block `X_UNUSED_KEY_REJECTED` | `all-keys`: any bad entry is `KEY_REJECTED`; `refuse` (1.2.1: the input is refused) | 1.3 step 2 "the public key must be a canonical encoding (y < p) of a point of prime order; any other key ... is `KEY_REJECTED` and no signature check is run" |
| `--reference-time` | `earlier` | `covering-token` (1.2.1) | 1.3 step 5 "the **earlier** of `issued_utc` and the genTime of the record's own token when a token covering the record is supplied, else `issued_utc`" |
| `--accuracy` | `widen` | `ignore` (1.2.1), `interval` (RFC 3161 2.4.2 ordering rule, `undetermined` when not provable) | 1.3 step 5 "A token's stated `accuracy` widens its time against \"committed before\"; a token stating none is taken at its genTime; `ordering` is ignored" |
| `--independence-rule` | `derived` | `stated-independent` (1.2.1: only a stated `independent` with the same party) | 1.3 step 8 "a stated `independence` that differs from the derived one is also `INDEPENDENCE_INCONSISTENT`" |
| `--time-agreement` | `truncate`: `committed_at` agrees if it equals genTime cut to its own precision | `exact` | step 5 "a `criteria.committed_at` that disagrees is `CRITERIA_TIME_MISMATCH`" (unchanged in 1.3) |
| `--tokens` | `structural` (imprint and genTime) | `pkix` (the time of a token that is not `verified` is not used) | 1.4.1 step 9 "The outcome fields cover imprint and time only"; `tsa_signature` "never changes any other outcome member" (so `pkix` is a local choice) |
| `--tsa-precedence` | `failed-first` | `evaluability-first` (the order reported for 1.4 by another verifier; not 1.4.1) | 1.4.1 step 9 "When a token has more than one defect, the value is `failed` if any check that can run fails; otherwise `no_signer`, then `unsupported`, then `untrusted`" |
| `--name-compare` | `exact` | `normalized` (NFKC, casefold, collapsed spaces) | property 3 names parties; no equality rule |
| `--unknown-fields` | `refuse` | `report` | profile silent, except where bc5a138 fixes the outcome: `receipt.tools.numbers_for_canonicalization` (vectors 52, 57), a `receipt.payment` outside its form (55) and the unsigned envelope `timestamp.digest_sha256` outside its form (step 6) are notes under both values |
| `--ed25519` | `strict` (canonical R, R not of small order, S < L) | `rfc8032` (RFC 8032 5.1.7 only) | the key itself is governed by `--key-rule` |
| `--correspondence` | `ids-required` (same ids, same `required`) | `strict` (titles too) | step 4 "check the results correspond to the criteria" |

Other decisions taken from the text:

- A criteria token whose imprint does not match gives `CRITERIA_TIMESTAMP_MISMATCH` and the fallback
  (`CRITERIA_COMMITMENT_UNVERIFIED`, `committed_at` used): 1.3 step 5 "Without a usable token (none, or one over
  other bytes), fall back to `committed_at`".
- An imprint matches only if `hashAlgorithm` is SHA-256 (OID 2.16.840.1.101.3.4.2.1) with absent or NULL parameters
  and the 32 bytes are equal (1.3 step 5 "a same-length imprint under another algorithm is not a match"; the
  parameters rule is RFC 5754 2).
- A supplied record token is always checked and, when it covers the record, enters the reference time, whatever the
  unsigned `envelope.timestamp` says (step 6: the unsigned `timestamp.digest_sha256` "never decides the outcome").
  The envelope metadata is only compared (`X_TIMESTAMP_METADATA_DISAGREES`, `X_TOKEN_SUPPLIED_RECORD_DECLARES_NONE`).
  Under 1.3 the unsigned `signature.key_id` no longer selects the key: it can only make the record
  `SIGNATURE_INVALID`. `signature.alg` must be `Ed25519`.
- Derived independence: `undeclared` when the producer has neither a non-blank name nor a key id; otherwise
  `self-checked` when the producer and checker names are equal or their keys collide; otherwise `independent`.
  `INDEPENDENCE_INCONSISTENT` is raised when the stated value differs (this includes a stated `self-checked` with
  distinct parties, and vector 20: stated `independent`, no producer). `SELF_CHECKED` follows the label.
- `CHECKER_NOT_SIGNER` is raised when `parties.checker.key_id` is null, unknown, or resolves to another public key
  than the one `receipt.key_id` names. A rejected key still counts as that key, so vectors 26 and 27 (checker =
  rejected signer key) give `KEY_REJECTED` alone. `KEY_COLLISION` compares public keys, not identifiers, and treats
  keys that differ only by a small-order component as equal.
- `PRODUCER_UNDECLARED` is raised when the producer has neither a non-blank name nor a key id ("follows the parties
  block (no producer named), whatever the record states").
- A result outside the vocabulary gives `RESULT_VOCABULARY`. In the verdict it counts as "not pass": required, and
  no required `fail`, gives `incomplete`.
- No problem code exists for a delivered file whose hash differs (step 3). This verifier reports `files` and
  `X_REMEDIATED_FILE_HASH_MISMATCH` and leaves the profile fields unchanged.
- With no required criterion, property 4 gives `pass` (vacuous). `X_NO_REQUIRED_CRITERION` is raised.
- Second 60 (`:60`, a leap second) is read as not a real calendar field in both time grammars (reading Q7): a
  token `genTime` with it gives no usable time (R4, omega-41) and a stated time with it is `RECEIPT_TIME_UNREADABLE`
  (R5). Until 0.5.0 both were refused.
- Years are read as the four digits of RFC 3339 `date-fullyear`, 0000 included (`0000-01-01T00:00:00Z` and a `genTime`
  `00000101000000Z` are real dates here); no vector or sentence of the profile fixes year 0000.

Readings of 1.3 that no published vector pins (each has its own vector in `vectors/` or a test):
- the key rule applies to the key named by `receipt.key_id`; a bad entry that signs nothing does not change the
  profile fields (`--key-rule all-keys` reads "any other key" as the whole key list): omega-28, omega-29;
- a `receipt.key_id` absent from the key file stays `SIGNATURE_INVALID` (the 1.3 text names no other code);
- a rejected key together with a differing envelope `signature.key_id` gives both `KEY_REJECTED` and
  `SIGNATURE_INVALID`;
- widening with the earlier-of rule: the commitment is taken at genTime + accuracy and the reference at
  min(`issued_utc`, covering genTime - accuracy), so "yes" needs the first strictly earlier than the second.
  With no stated accuracy this is exactly the earlier-of rule. A literal reading that first compares the covering
  genTime with `issued_utc` and then widens only a token that won gives a different answer on omega-50;
- `committed_at` (the fallback) and `issued_utc` carry no accuracy.

## What was read

Only these files; their URLs and SHA-256 values are in `SOURCES.json`, or given below for files that were read
but are not kept. The 1.2.1 sources were first fetched on
2026-10-18T06:14:50Z, the 1.3 sources at 2026-10-18T15:31Z:

- for 0.6.0, on 2026-10-28: `fonti/upstream_cb7e8f1/` (the README at cb7e8f1, committed 2026-10-27T23:42:17Z, and
  vectors 88-90; SHA-256 in `SOURCES.json`; `tools/fetch_sources.py --check` verifies 405/405 with them). Read: the
  diff of the README 85a310d..cb7e8f1 (step 10 "Canonical base64" and "Stated times", the three vector rows, the
  changelog's clarification note), and every member of 88-90 except `inputs`. `verifier/`, `interop/` and
  `composition/` at cb7e8f1 were not opened. The upstream head c3e9bf1 (2026-10-28T03:57Z, checked with a bare
  clone on 2026-10-28) changes only the implementations table of the README and `composition/`, and the next head,
  7cd4546 (2026-10-28T14:13:48Z, compared with c3e9bf1 through the GitHub API), one row of that table: the profile
  text is that of cb7e8f1. The profile author's answers on x402-foundation/tsc#4 (comment 6460276466, 2026-10-28T03:57Z;
  a non-canonical token: no bytes, `not_evaluated` without anchors, `failed` with them; a covering record token
  without a usable `genTime`: no token time, `issued_utc` is the reference) were read on the issue on 2026-10-28;
  they are answers, not the profile text, and are marked so in the readings table (Q3, Q10);
- for 0.6.0 (2026-10-27): `fonti/upstream_85a310d/` (profile 1.4.2 README and vectors 01-87,
  maximusrufus/work-acceptance-record@85a310d, committed 2026-10-27T09:47:47-07:00). The files were taken with
  `git show` from a clone of that commit made outside this repository, and are pinned in `SOURCES.json` with their
  raw.githubusercontent.com URLs; `tools/fetch_sources.py --check` verifies them (401/401 at that date; 405/405 with the cb7e8f1 files), and the README and vector 77
  were also downloaded from those URLs once and have the same SHA-256. Read: the whole README (step 10 "Profile 1.4.2
  rules", the changelog entry "Profile 1.4.2 (2026-10-27 ...)", steps 1-9, the vector table and the
  "Implementations" table); every member of vectors 58-87 except `inputs` (`description`, `expected`, `contributed_by`,
  `test_key_seeds`, `title`, `vector`, `spec`, `license`, `warning`), and the `inputs` of 84 and 85 (`receipt.tools`) where an outcome needed them; the commit subjects
  of bc5a138..85a310d (`git log`; one of them names the reference verifier's 1.4.2 rules, its diff was not read).
  **Not opened:** `verifier/` (the reference verifier and `check_payment.py` at 85a310d), `interop/` and
  `composition/`. Where step 10 leaves a case open, the reading taken here is marked **reading** in "Profile 1.4.2
  rules" and listed in "Readings not fixed by the vectors" as a question, not taken from the reference code. Also
  read: the brief of the project owner with this verifier's 0.5.0 outcomes on the 85a310d vectors (a bench outside
  this repository, run on 7c96866). RFC 4648 section 4 and 3.5 (canonical base64, pad bits) was applied from its known
  rules and not re-read;
- for 0.5.0 (2026-10-24): `fonti/upstream_bc5a138/` (profile 1.4.1 README and vectors 01-57,
  maximusrufus/work-acceptance-record@bc5a138) and `fonti/upstream_48ab8c9/` (vectors 01-59, the head of open PR #1),
  both fetched through `tools/fetch_sources.py` and checked by SHA-256; the README diff d79a737..bc5a138 was read in
  full. **Not clean-room on the payment form:** the function `_in_form` of bc5a138 `verifier/check_payment.py`
  (SHA-256 44343f91568d5be3…, lines 85-104) was opened, and the form above (byte lengths, decimal `amount` without leading zeros, either case of
  hexadecimal digits) is taken from it, beyond the README's own sentence on the form. The reference
  `verifier/war_verify.py` of bc5a138 (SHA-256 ac3ac35d9356cbb5…; the same file at 48ab8c9) was searched once with
  `grep -n -i 'unknown\|extra\|members\|set(.*) -\|keys()'` (three matching lines, none about members) and was
  otherwise not opened; it was run as a black box on this
  project's own probe documents (outcomes compared; the comparison is not reported here). The comments on x402-foundation/tsc#4 of 2026-10-24 by
  maximusrufus (vectors 58-59, the 1.4.1 clarification on unsigned attributes) and actaseal (candidate readings) were
  read, and the "Implementations" table of the README at master 8e00300; the text of the README at 48ab8c9 and the
  tsc#4 comments of 2026-10-23 were not read;
- for 0.4.1, Tetsurohhori's comment on x402-foundation/tsc#4 (issuecomment-6327691458, 2026-10-21T22:12:28Z) and, at
  aos-standard/catalog@8c210d1, `docs/runs/work-acceptance-record-cold/probe-status-imprint/README.md` (SHA-256
  6cb5120c0a9abf8a…) and the vector `probe-status-string-imprint.json` (66f9aeb761aae596…), fetched 2026-10-22 about
  02:10 CEST and run outside this repository. The probe's builder and that catalog's verifier were not opened; the
  construction in `tests/test_status_info.py` was written here from the README's description and then matched byte
  for byte to the vector's criteria response (one `UTF8String` holding the three values, `NULL` algorithm parameters);
- `fonti/upstream_d79a737/`: the profile 1.4.1 README as clarified for the anchor match (subject name and public
  key) and vectors 48-49 (maximusrufus/work-acceptance-record@d79a737, committed 2026-10-21T16:45:33Z, fetched
  2026-10-21 about 19:06 CEST). Vectors 01-47 of d79a737 have the blob ids of the 06d3b94 files (47/47, checked
  through the GitHub contents API, not re-fetched). `verifier/` was not opened; babyblueviper1's step 9 run
  (issuecomment-6321173684) and the profile author's reply (issuecomment-6321519766) were read;
- `fonti/upstream_06d3b94/`: profile 1.4.1 README with the optional `payment` member, and vectors 01-47
  (maximusrufus/work-acceptance-record@06d3b94, committed 2026-10-21T16:34:22Z, fetched 2026-10-21 about 18:45 CEST).
  Vectors 01-46 are byte-identical to 4daf721. `verifier/check_payment.py` and `verifier/war_verify.py` were not
  opened; the profile author's comment that announces the member (issuecomment-6321198568) and babyblueviper1's
  request (issuecomment-6320718286) were read;
- `fonti/upstream_4daf721/`: profile 1.4.1 README and vectors 01-46 (maximusrufus/work-acceptance-record@4daf721,
  committed 2026-10-21T14:52:14Z, fetched 2026-10-21 about 17:20 CEST). Vectors 01-36 are byte-identical to eb0f30b.
  `verifier/war_verify.py` was not opened;
- the comments on x402-foundation/tsc#4 of 2026-10-21: the profile author's announcement of 1.4.1
  (issuecomment-6319114209), magentixai (issuecomment-6316838063) and whawk46 (issuecomment-6313776392). The whawk46
  comment quotes and describes parts of the reference verifier at eb0f30b (its time-stamp imprint and genTime
  extraction, its number serialization, its independence and verdict checks, and the interface of its
  authority-signature function: its two arguments, the wrapper it skips, and that it does not bind the imprint it
  checks). It was read after 0.3.0 and before 0.4.0; the 0.4.0 changes are the step 9 rules of 1.4.1 (chain classes,
  the closed list of TSA key algorithms) and the `tsa_signature_accepted` member: the comment says nothing about how
  the reference classes chains or key types, and no quoted part was reproduced here;
- `fonti/upstream_eb0f30b/`: profile 1.4 README and vectors 01-36 (maximusrufus/work-acceptance-record@eb0f30b,
  committed 2026-10-20T16:00:02Z, fetched 2026-10-21 about 04:15 CEST). Vectors 01-27 are byte-identical to 42b4ed0
  (`tests/test_vectors.py`), and each file matches its git blob id in the commit tree. The commit also changes
  `verifier/war_verify.py`, the profile author's reference verifier: it was not opened;
- the profile author's comments on x402-foundation/tsc#4 that announce 1.4 (issuecomment-6294582057 and
  issuecomment-6295390438, 2026-10-20) and Tetsurohhori's report of a third phase-9 implementation
  (issuecomment-6303226273, 2026-10-20T22:30:33Z). That report was read before 0.3.0 was written and lists the order
  in which its checks run (no_signer, unsupported, failed, untrusted); on the order between values, this verifier
  is therefore not independent of it. Its code and addendum were not opened;
- `fonti/upstream_42b4ed0/`: profile 1.3 README and vectors 01-27 (maximusrufus/work-acceptance-record@42b4ed0,
  committed 2026-10-18T14:43:42Z). Vectors 01-11 are byte-identical to f7d8984. Vectors 12-23 have the same
  `inputs` as the copies listed below (12 is 12b); only metadata changed, and vector 20's `expected` (now with
  `INDEPENDENCE_INCONSISTENT`, the contributor's expectation stated in a `difference` member);
- the rulings comment of the profile author on x402-foundation/tsc#4 (issuecomment-6251239282, 14:44:09Z), read
  with `gh api`; the README text was checked for each ruling. A later comment of the same author
  (issuecomment-6251573298, posted 15:17:28Z, edited 15:44:33Z) is about their implementations and states no ruling;
- `fonti/upstream_f7d8984/`: profile 1.2.1 README and vectors 01-11 (maximusrufus/work-acceptance-record@f7d8984);
- `fonti/tetsurohhori_4f6cf49/`: proposed vectors 12-21 and `TEST_KEY.json`;
- `fonti/babyblueviper1_431525f/`: proposed vectors 22-23;
- `fonti/tetsurohhori_8ff69f4/`: proposed vectors `12b-signer-is-not-the-checker` and `22-criteria-token-sha1-imprint`,
  posted on 2026-10-18 at about 07:10Z;
- `fonti/issuer_274159c/`: the issuer's `selftest-pass.json`, its README and `checker-keys-live.json` (the live key file).
  Its `keys` equal the `keys` embedded in `selftest-pass.json`.

The following standards were fetched from rfc-editor.org on 2026-10-18 (the first 16 hex digits of each SHA-256 are
given): RFC 8785 (63d52294eb0e3f00), RFC 8032 (ed63657ff3893012), RFC 3161 (39fd17644ff2d654), RFC 5652
(dbd209ae7844031f), RFC 5280 (a2f2628c0a83b873), RFC 5816 (9a3eba6ecf14afc7), RFC 7493 (a44ccf1451a7bf4f),
RFC 3339 (9ab2b8864a85dca7) and RFC 5754 (13d095299ffec21b); RFC 4210 (64210d97dd49cf49, for `PKIFreeText`) on
2026-10-22. X.690 (DER) and the ESS attribute definitions
(RFC 2634, RFC 5035) were applied from their known rules and not re-read.

TSA certificates (in `roots/`, fetched from freetsa.org/files on 2026-10-18T06:16Z): `freetsa_cacert.pem`
(SHA-256 of the file 2151b611…, certificate fingerprint A6:37:9E:7C…) and `freetsa_tsa.crt`. No DigiCert root
was fetched: the record contains no DigiCert token.

The issuer README points to its own verifier (`war_check.py`). It was not opened, and no other verifier, builder or
runner for this profile was opened, except as stated for 0.5.0 above (the parts of the reference verifier quoted in
the whawk46 comment above were read in that comment only). For the composition section only, this project's own x402 acceptance-record
checker was read and run. The vectors' own descriptions state their contributors' readings. On the points those
descriptions decide, this verifier is not independent of them. The reading of each point is in "Switches" and in
the `reading` field of the new vectors. Vectors 24 and 25 of 1.3 are listed in the profile README as "case from
robertolocatelli81-dev", and the rulings comment says they "cover @robertolocatelli81-dev's omega-15 and omega-16",
two vectors of this project: agreement on 24 and 25 is not independent evidence.

## Readings not fixed by the vectors (`tests/test_readings_20261024.py`)

Candidate vectors listed on x402-foundation/tsc#4 on 2026-10-24, and what this verifier does with each (signed with a
test key over this verifier's canonical form; the RFC 8785 bytes are checked against Node v22.23.2 `JSON.stringify`
and the default `Array.prototype.sort`, which orders member names by UTF-16 code units):

| reading | outcome here | decided by |
|---|---|---|
| exponent forms with more than one significant digit (`1.5e-7`, `1.25e+22`) | serialized as ECMAScript does; the signed receipt passes; a signature over `1.5e-07` is `SIGNATURE_INVALID` | RFC 8785 3.2.2.3 |
| a member name outside the BMP | ordered by UTF-16 code units (`"\U0001F600"` before `"\uFF61"`), and a signature over code-point order is `SIGNATURE_INVALID`; from 0.6.0 the member `keys_utf16_order` of `receipt.tools` carries such names (85a310d vector 85, passes); elsewhere a receipt object has no such member: refused (a note under `--unknown-fields report`) | RFC 8785 3.2.3; 1.4.2 vector 85 |
| envelope `signature.key_id` other than the signed `receipt.key_id` | `SIGNATURE_INVALID` | step 2 |
| producer and checker naming the same `key_id`, or one public key listed under two ids with the producer named by the second | `KEY_COLLISION` and `INDEPENDENCE_INCONSISTENT` in both cases (the keys are compared, not the ids) | property 3, "The checker key must not equal the producer key" |
| fractional seconds in `issued_utc` | until 0.5.0 read as RFC 3339 allows; from 0.6.0 exactly three digits, any other count `RECEIPT_TIME_UNREADABLE` (**reading** of `[.fff]`) | 1.4.2 R5 (76) |
| base64 outside the alphabet, without padding, or base64url | until 0.5.0 refused; from 0.6.0 `SIGNATURE_INVALID` for the signature value, `KEY_REJECTED` for a key entry, "matches nothing" for a token or file | 1.4.2 R1 (60-63, 69) |
| upper-case hexadecimal in a hash field | until 0.5.0 refused; from 0.6.0 it matches no digest (`CRITERIA_HASH_MISMATCH`, `CRITERIA_TIMESTAMP_MISMATCH` for `criteria.sha256`) | 1.4.2 R2 (67) |
| `imprint_match` with no issue time (a receipt without `issued_utc`, record token matching) | refused: `issued_utc` is a member of every published receipt | profile silent; step 5 names `issued_utc` |

### Profile 1.4.2: readings not fixed by the text (questions for the profile author)

Each is pinned in `tests/test_profile142.py`; none was taken from the reference verifier, which was not opened.

| # | case | reading taken here | why it is open |
|---|---|---|---|
| Q1 | a non-canonical `public_key_base64` in an entry no party names and not the signer's | `KEY_REJECTED` | R1 "a non-canonical public key is `KEY_REJECTED`" has no restriction; the step 2 point rule is restricted to the signing key (28), R3 is not (79); no vector |
| Q2 | `criteria_tsr_base64` not canonical | `CRITERIA_TIMESTAMP_MISMATCH` and fallback with `CRITERIA_COMMITMENT_UNVERIFIED`, no `tsa_signature.criteria` | R1 "matches nothing": a token over other bytes, or no token at all (then no problem code)? **Closed at cb7e8f1 (2026-10-27): vector 90 fixes this reading (89 for the criteria file)** |
| Q3 | `tsa_signature` for a token that is not canonical base64 | `not_evaluated` without anchors, `failed` with anchors (as first written for 85a310d: member absent even with anchors) | step 9 has no value for a token that cannot be read. **Answered by the profile author on x402-foundation/tsc#4, comment 6460276466 of 2026-10-28 ("Without anchors, `tsa_signature` is `not_evaluated`; with anchors it is `failed`, as for any malformed token"), followed here; not yet in the profile text or a vector** |
| Q4 | a record digest that is not upper case but still not 64 lower-case hex digits (wrong length, other characters) | refused | R2 names upper case only |
| Q5 | `.fff` in `YYYY-MM-DDTHH:MM:SS[.fff]Z` | exactly three digits; `.5` is `RECEIPT_TIME_UNREADABLE` | RFC 3339 allows any number of digits; the pattern shows three |
| Q6 | an unreadable `committed_at` when a usable criteria token is present | `CRITERIA_TIME_MISMATCH`, the token decides "before" (as first written for 85a310d: `RECEIPT_TIME_UNREADABLE`, `no`) | R5 "a present time in another form that step 5 uses": step 5 uses `committed_at` for `CRITERIA_TIME_MISMATCH` too; 76 has no token. **Closed at cb7e8f1 (2026-10-27): vector 88 fixes the other reading ("step 5 uses `committed_at` only when no usable criteria token supplies the time"), followed here** |
| Q7 | second 60 (`...235960Z`, `T23:59:60Z`) | not a real calendar field: no usable time / unreadable | R4 and R5 say "real calendar fields"; leap seconds exist in UTC |
| Q8 | rounding and `accuracy` together | round to the millisecond first, then add (criteria) or subtract (reference) the accuracy | R4 does not order the two; equal results unless the accuracy has microseconds |
| Q9 | `CRITERIA_TIME_MISMATCH` and the millisecond rule | unchanged: token time truncated to `committed_at`'s precision | R4 speaks of "before"; 66 says `committed_at` is "compared to the second" |
| Q10 | a record token whose `genTime` is not usable | `receipt_timestamp` still from the imprint (`imprint_match`), the token is no reference time | R4 "the token is treated as giving none" is about time; step 6 is about the imprint. **Confirmed by the profile author on x402-foundation/tsc#4, comment 6460276466 of 2026-10-28 ("there is no token time, and `issued_utc` is the reference time in step 5"); not yet in the profile text or a vector** |
| Q11 | authority check of a token whose `genTime` is not usable, with anchors | `failed` (validity at genTime cannot be shown) | step 9 has no value for it |
| Q12 | `CHECKER_NOT_SIGNER` when the checker's `key_id` names another identifier for the signer's key | raised (identifiers compared) | R7 compares `key_id`s; property 3 compares keys for independence; until 0.5.0 not raised |
| Q13 | an envelope `timestamp.digest_sha256`, or `receipt.payment` or one of its members, of the wrong type | a note, as in 0.5.0 | step 6 "never decides the outcome" and vector 55 "changes no outcome" against R8 "refused" |
| Q14 | a stated checker `key_id` that is empty or not listed | derived `self-checked` (and `CHECKER_NOT_SIGNER`) | R6 says "a party's `key_id`"; 80-81 test the producer only |
| Q15 | an empty string as the signed `receipt.key_id` or the envelope `signature.key_id` | refused (`receipt.key_id is empty`, `signature.key_id is empty`), as until 0.5.0; a non-empty identifier listed by no entry stays `SIGNATURE_INVALID` | step 2 names no code for an identifier that names no key; R6 reads an empty `key_id` as a value for a party only (80); no vector |

The same test file pins two rules that are not among those readings: the unsigned envelope `timestamp.digest_sha256`
(step 6, a record token whose imprint matches and a `digest_sha256` outside its form: `imprint_match`,
`X_TIMESTAMP_METADATA_MALFORMED`; refused until 0.4.1) and the member of `receipt.tools` of vectors 52 and 57.

## Results, profile 1.4.2 at 85a310d (measured 2026-10-27, version 0.6.0)

Defaults: the 87 vectors of 85a310d and the live record (`tools/score.py`, `results/score_default.txt`): 88/88
documents, 803/803 fields. Vectors 88-90 of the clarification at cb7e8f1 (2026-10-27T23:42Z): 3/3 documents, 27/27
fields (`tests/test_profile142.py`, `test_cb7e8f1_88_to_90`); as first written for 85a310d, 0.6.0 refused 88 for the
vector member `proposed_by` and, with that member read as metadata, disagreed with it on two fields
(`RECEIPT_TIME_UNREADABLE` and `no`, expected `CRITERIA_TIME_MISMATCH` and `yes`: Q6). The 1.4.1 sets are unchanged: bc5a138 58/58 and 537/537 (`--set bc5a138`,
`results/score_set_bc5a138.txt`), 48ab8c9 60/60 and 557/557, 06d3b94 48/48 and 441/441, 1.4 37/37 and 332/332,
1.3 28/28 and 245/245; the 1.2.1 round gives 24/26 with the defaults (old 12 and old 20, as in 0.5.0) and 25/26 with
`--profile 1.2.1` (22, as in 0.1.0). No old set changes outcome under 1.4.2, so no old set needs an option of its own;
the inputs and `expected` objects of 01-57 at 85a310d are those of bc5a138 (`tests/test_profile142.py`). Version 0.5.0
(7c96866) on the 85a310d vectors: 63/87 documents, 609/794 fields (84-87 refused for the vector member
`test_key_seeds`, each counted 0/9, as `tools/score.py` counts a refused document whose `expected` has nine fields);
with that member read as metadata, 65/87 and 627/794 (both measured on a copy of 7c96866 with the 0.6.0
`tools/score.py`, the refusal of a vector member caught outside it).

Our own vectors (`vectors/`, 52): 52/52. One changes its expectation because of 1.4.2: `omega-41` (criteria token
`genTime` with second 60) was refused until 0.5.0 and now gives no usable time (R4; its `reading` member says so).

Each other value of each switch on the 88 documents (`results/score_*.txt`):

| switch | documents agreeing | disagreeing vectors |
|---|---|---|
| `--reference-time covering-token` | 87/88 | 22 |
| `--accuracy ignore` | 87/88 | 29 |
| `--accuracy interval` | 41/88 | 47 vectors: `undetermined` where the tokens state no `accuracy` |
| `--key-rule all-keys` | 87/88 | 28 |
| `--key-rule refuse` | 82/88 | 26, 27, 28, 69, 75, 79 |
| `--independence-rule stated-independent` | 85/88 | 20, 80, 81 |
| `--key-id-source envelope` | 86/88 | 75, 86 |
| `--key-id-agreement require` and `ignore` | 86/88 each | 64, 86 |
| `--time-agreement exact` | 86/88 | 66, 68 |
| `--tsa-precedence evaluability-first` | 85/88 | 44, 45, 46 |
| `--profile 1.2.1` | 75/88 | 20, 22, 26, 27, 28, 29, 64, 69, 75, 79, 80, 81, 86 |
| `--name-compare normalized`, `--correspondence strict`, `--ed25519 rfc8032`, `--unknown-fields report` | 88/88 each | none |

## Results, profile 1.4.1 at bc5a138 (measured 2026-10-24, version 0.5.0)

Defaults: the 57 vectors of bc5a138 and the live record (`tools/score.py`, `results/score_default.txt`): 58/58
documents, 537/537 fields. Open PR #1 at 48ab8c9 (one commit on master 8e00300, adding vectors 58 and 59; after bc5a138
master rewrote the descriptions of 13 vectors and added an implementations table to the README, inputs and `expected`
unchanged): 60/60 documents,
557/557 fields (`--set 48ab8c9`, `results/score_set_48ab8c9.txt`). The 06d3b94 set of the next section still gives
48/48 and 441/441 (`--set 1.4.1`). The inputs and `expected` objects of 01-47 in bc5a138 and 48ab8c9 are those of
06d3b94 (`tests/test_vectors.py`). Version 0.4.1 on the bc5a138 set: 51/57 vectors, 480/528 fields; the six it does
not agree with are the rules this version follows (50 and 51 refused for the `statusString`; 52 and 57 refused for
the member `numbers_for_canonicalization` of `receipt.tools`; 55 refused for the payment form; 54 `untrusted` instead
of `failed`).

Positive controls: a verifier that always answers "valid, pass, no codes" agrees only with 30, 47, 52, 55 and 57,
whose expected outcome is exactly that; a problem code added to every `expected` is caught on all 58 (and all 60 of
48ab8c9); our outcome with `tsa_signature` removed disagrees exactly on the 20 vectors with evaluated tokens (31-35,
37-42, 44-46, 48-51, 53, 54).

Each other value of each switch on the 58 documents (`results/score_*.txt`):

| switch | documents agreeing | disagreeing vectors |
|---|---|---|
| `--reference-time covering-token` | 57/58 | 22 |
| `--accuracy ignore` | 57/58 | 29 |
| `--accuracy interval` | 28/58 | 30 vectors: `undetermined` where the tokens state no `accuracy` |
| `--key-rule all-keys` | 57/58 | 28 |
| `--key-rule refuse` | 55/58 | 26, 27, 28 |
| `--independence-rule stated-independent` | 57/58 | 20 |
| `--tsa-precedence evaluability-first` | 55/58 | 44, 45, 46 |
| `--profile 1.2.1` | 52/58 | 20, 22, 26, 27, 28, 29 |
| `--key-id-source envelope`, `--time-agreement exact`, `--key-id-agreement require` and `ignore`, `--name-compare normalized`, `--correspondence strict`, `--ed25519 rfc8032`, `--unknown-fields report` | 58/58 each | none |

`--tokens pkix` is not in the table: it needs `--tsa-roots`, and by design it does not use the time of a token that is
not `verified`, so the fixture tokens of 01-30 do not give the vectors' outcomes.

## Results, profile 1.4.1 at 06d3b94 (measured 2026-10-21)

The 47 vectors of 06d3b94 and the live record (`--set 1.4.1`, `results/score_set_1_4_1_06d3b94.txt`; the default
until 0.4.1): 48/48 documents, 441/441 fields, also with 0.5.0. Vectors 01-36 are byte-identical to eb0f30b and 01-46 to 4daf721 (`tests/test_vectors.py`).
Version 0.4.1 gives the same 48/48 documents and 441/441 fields (measured 2026-10-22). Vector 47 (a passing receipt whose signed body carries `payment`) agrees on its 9 fields. Vectors 48 and 49 of
d79a737 (a signer without `id-kp-timeStamping`; an issuer without the CA flag) agree too, both `failed`, each on the
rule its name states (`tests/test_nemesis_141b.py`); they are not in the scored set, which stays at 06d3b94. Vectors
37-46, `tsa_signature` compared key by key:

| vector | expected | ours |
|---|---|---|
| 37 test PKI: root, intermediate, TSA (control) | `verified` | `verified` |
| 38 as 37, intermediate expired before genTime | `failed` | `failed` |
| 39 signed `contentType` `id-ct-authData` | `failed` | `failed` |
| 40 RSASSA-PSS | `verified`, `unsupported` accepted | `unsupported` |
| 41 ECDSA P-256 | `verified` | `verified` |
| 42 ECDSA P-521 | `unsupported` | `unsupported` |
| 43 31's tokens, `tsa_roots_base64: []` | `not_evaluated` both | `not_evaluated` both |
| 44 P-521 and a messageDigest that does not match | `failed` | `failed` |
| 45 no certificates and a messageDigest that does not match | `failed` | `failed` |
| 46 P-521 and an ESS hash that does not match | `failed` | `failed` |

Positive controls:
- version 0.3.0 run unchanged agrees on 43 of the 46 vectors: 38 `untrusted` (expected `failed`), 42 `verified`
  (expected `unsupported`), and 40 refused for the unknown vector member `tsa_signature_accepted`;
- our outcome with `tsa_signature` removed agrees on 36 and 43 (`not_evaluated`) and disagrees on the 14 others of
  31-46;
- a value accepted by `tsa_signature_accepted` for one token is not accepted for the other, and without the member
  `unsupported` disagrees with 40;
- a verifier that always answers "valid, pass, no codes" agrees only with vectors 30 and 47, whose expected outcome
  is exactly that;
- a problem code added to every `expected` is caught on all 48 documents;
- the receipt grammar without `payment` refuses vector 47, and a `payment` edited after signing is
  `SIGNATURE_INVALID` (`tests/test_payment141.py`).

Each other value of each switch on the 48 documents (`results/score_*.txt`):

| switch | documents agreeing | disagreeing vectors |
|---|---|---|
| `--reference-time covering-token` | 47/48 | 22 |
| `--accuracy ignore` | 47/48 | 29 |
| `--accuracy interval` | 22/48 | 26 vectors: `undetermined` where the tokens state no `accuracy` |
| `--key-rule all-keys` | 47/48 | 28 |
| `--key-rule refuse` | 45/48 | 26, 27, 28 |
| `--independence-rule stated-independent` | 47/48 | 20 |
| `--tsa-precedence evaluability-first` | 45/48 | 44, 45, 46 |
| `--profile 1.2.1` | 42/48 | 20, 22, 26, 27, 28, 29 |
| the switches not listed | 48/48 each | none |

Cases the published vectors do not reach (`tests/test_tsa_signature14.py`, a throw-away TEST TSA built on vector
31's record, under both precedences): ECDSA P-256 and P-384 and RSA PKCS#1 v1.5 `verified`; RSASSA-PSS, ECDSA P-521
and an Ed25519 TSA key `unsupported`; a chain through an intermediate CA `verified`; an anchor expired before genTime
`verified` (only issuers other than the anchor must be valid then); an intermediate expired at genTime or without
the CA flag, and an issuer without keyCertSign or without basicConstraints, `failed` when the chain reaches the
anchor; the expired intermediate and the issuer without keyCertSign or basicConstraints `untrusted` under another
anchor; intermediate missing from the token `untrusted`; a cross-signed copy of the anchor inside the token, or the
cross-signed copy supplied as the anchor, `verified`, the anchor's name with another key `untrusted`
(`tests/test_nemesis_141b.py`); signer certificate expired at genTime (also when it is itself the anchor), EKU serverAuth, ESS
absent or over another certificate, a message-digest over other bytes `failed`; a token without SignerInfo (the
shape of 01-30) `no_signer`. For every case, every other outcome member is the same as without anchors. Three cases
separate the precedences: RSASSA-PSS or P-521 with a wrong message-digest (`failed` / `unsupported`) and no
certificates with a wrong message-digest (`failed` / `no_signer`).

## Results, profile 1.4 (measured 2026-10-21)

Measured with 0.3.0; `results/` now holds the 1.4.1 runs. Version 0.4.0 still gives 37/37 documents and
332/332 fields on this set (`--set 1.4`, `results/score_set_1_4.txt`).

The 36 vectors of eb0f30b and the live record: 37/37
documents, 332/332 fields. 31-36 compared on `tsa_signature` key by key, an absent key read as `not_evaluated`:

| vector | `tsa_signature` (ours = expected) |
|---|---|
| 31 FreeTSA, FreeTSA root | criteria `verified`, receipt `verified` |
| 32 DigiCert, DigiCert Trusted Root G4 | `verified`, `verified` |
| 33 FreeTSA tokens, DigiCert root | `untrusted`, `untrusted` |
| 34 one bit in the criteria token's signature | `failed`, `verified` |
| 35 criteria token with certReq=false | criteria `no_signer` |
| 36 no anchors | `not_evaluated`, `not_evaluated` |

Same result with `--tsa-precedence evaluability-first`. Positive controls: version 0.2.0 run unchanged agrees on 30/36 vectors (31-35 refused for the unknown member
`inputs.tsa_roots_base64`; 36 disagrees because 0.2.0's comparison did not read an absent `tsa_signature` as
`not_evaluated`). Our outcome with `tsa_signature` removed agrees on 36 and disagrees on 31-35. Each of the 55 other
values of each key of 31-36 written into `expected` is detected (55/55, `tests/test_tsa_signature14.py`). A verifier that always answers "valid,
pass, no codes" agrees with one document of 37: vector 30, whose expected outcome is exactly that.

Each other value of each switch on the 37 documents (0.3.0):

| switch | documents agreeing | disagreeing vectors |
|---|---|---|
| `--reference-time covering-token` | 36/37 | 22 |
| `--accuracy ignore` | 36/37 | 29 |
| `--accuracy interval` | 13/37 | 24 vectors: `undetermined` where the tokens state no `accuracy` |
| `--key-rule all-keys` | 36/37 | 28 |
| `--key-rule refuse` | 34/37 | 26, 27, 28 |
| `--independence-rule stated-independent` | 36/37 | 20 |
| `--profile 1.2.1` | 31/37 | 20, 22, 26, 27, 28, 29 |
| `--tsa-precedence evaluability-first` and the switches not listed | 37/37 each | none |

## Results, profile 1.3 (measured 2026-10-18)

Profile 1.3 set (`--set 1.3`, `results/score_set_1_3.txt`): the 27 vectors of 42b4ed0 and the live record, compared field by field, with code lists
compared as sets (`tools/score.py`, `results/score_default.txt`):

| document | fields | outcome |
|---|---|---|
| 01-20, 22-27 | 9/9 each | agree |
| 21-unknown-schema | 2/2 (`refused`, `reason`) | agree |
| selftest-pass (live record) | 9/9 | agree |

Total: 28/28 documents, 245/245 fields.

Vector 20, both readings reported. The file's `expected` (profile author) has `INDEPENDENCE_INCONSISTENT` and the
`PRODUCER_UNDECLARED` warning; this verifier agrees. Its `difference` member states the contributor's expectation,
"problem_codes [] (warning only)"; against it this verifier disagrees on `problem_codes` (ours
`INDEPENDENCE_INCONSISTENT`). The sentence that decides it is 1.3 step 8: "a stated `independence` that differs from
the derived one is also `INDEPENDENCE_INCONSISTENT`" (stated `independent`, derived `undeclared`). With
`--independence-rule stated-independent` the two results swap: the contributor's expectation agrees, the file's
does not.

Each other value of each switch, on the same 28 documents (measured 2026-10-18; `results/` now holds the 1.4 runs,
listed under "Results, profile 1.4"):

| switch | documents agreeing | what changes |
|---|---|---|
| `--reference-time covering-token` | 27/28 | 22: `yes` and no problem, expected `no` and `CRITERIA_COMMITTED_AFTER_CHECK` |
| `--key-rule refuse` | 26/28 | 26 and 27 refused, expected `KEY_REJECTED` |
| `--independence-rule stated-independent` | 27/28 | 20, as above |
| `--accuracy interval` | 12/28 | 16 "yes" become `undetermined`: no vector token states an `accuracy` |
| `--profile 1.2.1` (all six 1.2.1 readings) | 24/28 | 20, 22, 26, 27 |
| `--key-id-source envelope`, `--key-id-agreement require`, `--key-id-agreement ignore`, `--key-rule all-keys`, `--accuracy ignore`, `--time-agreement exact`, `--name-compare normalized`, `--correspondence strict`, `--ed25519 rfc8032`, `--unknown-fields report` | 28/28 each | none: no 1.3 vector separates them (own vectors and tests do) |

Version 0.1.0 of this verifier (the previous commit), run unchanged on the same 28 documents with vector 20's
`difference` member removed (0.1.0 refuses unknown vector members), also gives 24/28 with the same four
disagreements; `--profile 1.2.1` reproduces it.

The 1.2.1 round (23 vectors, 12b, 22-sha1 and the live record, `--set 1.2.1`): with `--profile 1.2.1`, 25/26
documents and 225/227 fields, as measured for 0.1.0 (only 22 disagrees). With the 1.3 defaults, 24/26 and 224/227:
22 now agrees; the old 12 (`signature.key_id` hori-cold-test-2, signed `receipt.key_id` hori-cold-test-1) gives
`SIGNATURE_INVALID` (1.3: "12b replaces 12"); the old 20 gives `INDEPENDENCE_INCONSISTENT` (1.3 amended 20).

Positive controls of the scoring bench: a verifier that always answers "valid, pass, no codes" agrees with 0/28
documents. Corrupting one expected field in every vector is detected 28/28 (`tests/test_vectors.py`).

## Beyond the profile

### RFC 3161 validation of the live record (`--tokens pkix`)

Both tokens of `selftest-pass.json` (criteria token, genTime 2026-10-18T00:52:03Z, and record token,
00:52:09Z) are checked as follows:

- one SignerInfo;
- the content-type and message-digest attributes;
- the ESS signing-certificate attribute binding the signer certificate (the live tokens use ESSCertID v1, SHA-1);
- the signature over the DER signed attributes;
- the EKU, exactly id-kp-timeStamping and critical;
- `TSTInfo.tsa` names the signer;
- every certificate valid at genTime;
- a path to the root fetched from freetsa.org (the root embedded in the token is not trusted).

Result: `valid` for both, and `openssl ts -verify` agrees. Both tokens carry `ordering` TRUE and the same TSA name,
so under RFC 3161 2.4.2 their order is provable even though neither has an `accuracy` field.

Fifteen cases from a throw-away test TSA give the positive controls, and each is compared with
`openssl ts -verify` (OpenSSL 3.0.22). Twelve cases agree with OpenSSL: the two valid tokens (ESS v1 and v2), and
ten invalid ones (signature flipped, message-digest wrong, no ESS attribute, ESS hash of another certificate, two
SignerInfos, EKU not critical, EKU serverAuth, EKU timeStamping plus codeSigning, no EKU, signed by another key).
Three cases differ:
- a token whose TSA certificate had expired at genTime, and one whose TSA certificate was not yet valid at genTime.
  `openssl ts -verify` checks certificates at the current time unless `-attime` is given (its documented default);
  with `-attime` set to genTime it rejects both (measured). This verifier checks every certificate at genTime. That
  is a choice of validation time (RFC 5280 6.1.1), not a sentence of RFC 3161 about the TSA certificate.
- a token whose content-type attribute is id-data while `eContentType` is id-ct-TSTInfo. RFC 5652 11.1 says the two
  MUST match. OpenSSL 3.0.22 accepts it; the missing check is a known open OpenSSL issue (openssl/openssl#9009,
  2019). This verifier rejects it.

OpenSSL 3.0.22 refuses to parse all 31 token occurrences (11 distinct tokens) in the 25 vectors of the 1.2.1 round
(`Field=signer_info ... field missing`; not re-run on the 1.3 vectors 24-27, whose README now calls the vector tokens
"imprint-and-time fixtures, not valid RFC 3161 tokens"). They omit
`signerInfos`, which RFC 5652 5.1 does not make optional. In `--tokens structural` mode they are accepted and
flagged `X_TOKEN_NOT_CMS_CONFORMANT`. In `--tokens pkix` mode they are refused.

### Ed25519 edge cases (`tools/ed25519_edges.py`, `results/ed25519_edges.txt`)

| case | `cryptography` engine alone | RFC 8032 pure | this verifier, strict |
|---|---|---|---|
| identity public key, R = identity, S = 0, any message | accepts | accepts | rejects; as the signer's key, `KEY_REJECTED` with no signature check (vector 26) |
| non-canonical public key (y = 1 + p), same signature | accepts | rejects | rejects; `KEY_REJECTED` (vector 27) |
| S + L | rejects | rejects | rejects |
| public key of order 2, R = identity, S = 0 | 29 of 64 messages | 29 of 64 | 0 |
| key A + T8, signed by A's scalar with k hashed over A + T8 | 35 of 256 messages (this seed; about 1 in 8 expected) | 35 of 256 | 0 |
| same, grinding the nonce for one chosen message | succeeds at try 2 here; about 8 tries expected | | |

The first two rows are known behaviour: an identity public key with R = identity and S = 0 verifies under RFC 8032
itself, and OpenSSL and pyca/cryptography accept a non-canonical public-key encoding (the classes of
ed25519-speccheck cases 0 and 11, published in 2020). They were measured again on 2026-10-18 with
`cryptography` 50.0.1 and 50.0.2 and with the `openssl` 3.0.22 command line. The last two rows show one private scalar producing signatures under two public keys with different
bytes. A `KEY_COLLISION` test that compares key bytes or key ids misses this; a party can also present two unrelated
keys, which no key comparison can detect. This verifier rejects keys that are not canonical or not of prime order
(`KEY_REJECTED`, profile 1.3; refused under `--profile 1.2.1`) and compares keys modulo the small-order subgroup.
The "strict" column is the signature primitive (`ed25519_verify`); the key rule runs before it, and
`tests/test_profile13.py` checks that no signature check runs for a rejected key (8 key encodings).

### Generative attack (`tools/fuzz.py`, `results/fuzz.txt`)

599 generated cases in 10 families, each with an expectation written from the text (profile 1.3; at 1.3 five
expectations and one case's `issued_utc` changed and one case was added, each with the sentence in `tools/fuzz.py`;
at 0.5.0 the 6 wrong-type cases at the unsigned envelope `timestamp.digest_sha256` expect the outcome of the
unaltered record, see "Closed by construction"; at 0.6.0 the `genTime` and stated-time expectations follow R4 and R5,
and the time family gains two cases). This verifier meets all 599. The deliberately lax verifier
`tools/lax_verify.py` is the positive control: it fails 556, and wrongly reports 411 as accepted as stated (554 and
410 at 0.5.0; 560 and 416 before the 6 envelope expectations changed).

| family | cases | lax verifier fails |
|---|---|---|
| unknown member at every object level | 21 | 21 |
| duplicate member at every object level | 21 | 21 |
| wrong type at every leaf | 418 | 406 |
| lone surrogate in every receipt string | 40 | 39 |
| numbers (1e21, 5e-324, 1.0, 2^53+1, -1, 1E2, -0, 0) | 24 | 18 |
| DER / TSTInfo (lengths, trailing bytes, all same-length hash OID swaps, params, nonce/extension smuggling, GeneralizedTime grammar, ordering FALSE, status) | 41 | 36 |
| Ed25519 | 5 | 3 |
| key_id confusion across envelope, receipt and parties | 7 | 4 |
| time ties and grammar | 12 | 7 |
| criteria file bytes (BOM, CRLF, NFC/NFD, trailing newline) | 10 | 1 |

### Composition with a counterparty acceptance (`tools/compose.py`, `results/compose.txt`)

`~/progetti/x402-acceptance-check-omega/acceptance_check.py` (commit 075ae1b) was run unchanged, on its own
grammar:

- a work-acceptance `receipt` passed as `accepted_record` is refused (input_error: 17 unknown members). Its
  `accepted_record` is a flat object of strings.
- a string projection (`issuer`, `issuer_kid`, `terms_sha256` = `criteria.sha256`, `outcome_sha256` =
  `files.remediated.sha256`, `outcome_at`, `record_id` = `war-sha256:` + SHA-256 of the canonical receipt) is
  `verified`.
- `outcome_at` must have exactly three fractional digits; `issued_utc` copied as is (seconds) is refused.
- the same acceptance stays `verified` when the relying party holds a different work-acceptance record. It also
  stays `verified` when the accepted record's recomputed verdict is `fail`. Only the glue check in `compose.py`
  catches these: `record_id` must equal the SHA-256 of the canonical receipt of the record held (the first case),
  and the relying party must read that record's recomputed verdict (the second case: the record verifies and is
  bound, and its verdict is `fail`).
- an acceptance signed with the checker's own key gives `acceptance_signer_is_issuer`, so the two parties stay
  separate.

Missing for an unchanged composition: a member carrying the work-acceptance digest as a checked binding, not as a
free-form `record_id`; one time format; and a rule saying that the relying party verifies the referenced record.

## Tests

```
python3 tools/fetch_sources.py                   # third-party inputs, pinned by SHA-256 (needs network once)
python3 -B -m unittest discover -s tests          # 205 tests
sh tools/run_results.sh                           # regenerates results/ (scores, fuzz, Ed25519, live record, composition)
```

Measured on 2026-10-28 (0.6.0): 205/205 pass on Python 3.9.25, 3.11.2 and 3.13.15, each with `cryptography`
50.0.1; on Python 3.11.2 with `cryptography` 40.0.0, 205/205 pass; with 39.0.2, 43 of the 205 fail by design (35 failures and 8 errors: the check behind `cannot_run`, `Certificate.verify_directly_issued_by`, needs 40.0.0).
The 41 tests of `tests/test_profile142.py` (profile 1.4.2): 32 fail on the 0.5.0 code (7c96866, with the 0.6.0 tests
and tools copied in); the other 9 are controls or cases 0.5.0 already gave the same way (canonical signature,
canonical alias collision, `--key-rule refuse`, 01-57 unchanged, usable `genTime` forms, readable stated times,
envelope `key_id`, `--profile 1.2.1`, reading Q8 at whole milliseconds). `tools/mutate142.py`: 40 targeted mutants, 40/40 killed, of the 0.6.0 lines (R1-R10, the cb7e8f1 rule of vector 88 and its vector member `proposed_by`, the `tsa_signature` of a non-canonical token, measured 2026-10-28 on Python 3.11.2), each caught by at
least one test, after a control run of the unmutated copy through the same driver; one first written,
"R1 b64 length not checked", was removed as equivalent (`b64decode(validate=True)` and the re-encoding comparison
already refuse every other length; over 2,675,076 strings, 0 differences, while a control without the re-encoding
comparison differs on 168). `tools/mutate14.py` (the 68 mutants of 0.3.0-0.5.0) had three patterns moved by 0.6.0
edits (same mutants, new text): 68/68 killed (2026-10-27, Python 3.11.2). The fuzz bench (`tools/fuzz.py`): 599/599, with the genTime and stated-time
expectations rewritten from R4 and R5 (until 0.5.0: refused).

Measured on 2026-10-24 (0.5.0): 164/164 pass on Python 3.9.25 and 3.13.15 with `cryptography` 50.0.2, on 3.11.2 with
50.0.1, and on 3.11.2 with `cryptography` 40.0.0. With 39.0.2, 41 of 164 fail by design and the other 123 pass: each failing test
expects a TSA value or check and gets the check that cannot run instead. On the 1.4.1 set with 39.0.2, the 14
documents with anchors all report `cannot_run` (exit 74 for 31, 38 and 42, measured) and every `tsa_signature`
value is `not_evaluated`; none is an evaluated value. Every test file has its positive control:
- the scoring bench fails an accept-always verifier (0/28 on 1.3; on 1.4 only vector 30, on 1.4.1 at 06d3b94 only
  30 and 47, at bc5a138 only 30, 47, 52, 55 and 57, see above);
- 18 of the 164 tests fail on the 0.4.1 code, the ones that state a 0.5.0 rule; the other new tests pin behaviour
  0.4.1 already had and pass there (measured on a checkout of 0.4.1 with the 0.5.0 tests, tools and vectors copied in);
- 68 targeted mutants of the 0.3.0, 0.4.0, 0.4.1 and 0.5.0 changes (value classes, chain classes with and without the anchor,
  the anchor's exemption from the genTime check, the signer's own check whatever the anchors, the closed list of TSA
  key algorithms read from the certificate, precedence, anchors, `tsa_signature_accepted`, comparison, the "never
  changes another member" rule, the chain API guard, the anchor among the issuer candidates, the `payment` grammar,
  the `PKIStatusInfo` grammar; for 0.5.0 the note on a `statusString` that is not UTF-8, issuer defects without the
  anchor, the member of `receipt.tools` of vectors 52 and 57 and its type, every rule of the payment form and its note,
  the unsigned envelope `timestamp.digest_sha256` and the form of the other envelope members, the default of
  `--unknown-fields`) are each caught by at least one test (68/68, `tools/mutate14.py`, which exits
  non-zero on a survivor or on a mutant whose pattern no longer applies). Of the 62 first written for 0.5.0, one
  ("expired signer classed as issuer defect") became equivalent once issuer defects are `failed` too and was removed:
  the same call with the same message, and over 113 vector documents and 11 test-PKI tokens with expired signers the
  full `tsa_signature` details are identical, while a control without the signer's validity check differs on 6 of the
  11. For 0.3.0, a second run of 24 mutants
  on the same lines by the review of 0.3.0 left 2 equivalent ones (the `anchors is roots` reuse of the pkix result
  and the narrowed `except` behind the chain API guard: 0 differences over 235 runs, a control mutant 7) and
  the tests of `tests/test_nemesis_14.py` for the rest; 4 of its 14 tests fail on the 0.3.0 code as first written
  (three tracebacks on malformed tokens or anchors, one on the type of a replaced `inputs.tsa_roots_base64`);
- each 1.3 rule in `tests/test_profile13.py` has a control case (its 1.2.1 reading, another switch value or an
  input on the other side of the rule), and each of the 14 own vectors with an `expected_1_2_1` disagrees under
  the other reading;
- the JCS table fails a naive `repr` (10/24 rows wrong);
- each Ed25519 vector fails with one flipped byte;
- every TSA case is compared with `openssl ts -verify`;
- the generative attack catches the lax verifier in every family.

`tests/nemesis_r1_check.py` and `tests/_nemesis_forge.py` come from the first independent review of this verifier,
and `tests/test_nemesis_r2.py` (7 tests) from the second; each of its tests kills a mutant that survived the battery
below (unimplemented TSA signature algorithm, certificate validity bounds, TSTInfo.tsa name, empty signerInfos,
ordering tie, producer key in the key file, y = p).
They are kept unchanged except the subprocess flags and, for 0.3.0, check F3 (`--tsa-roots` without `--tokens pkix`
is now valid; the check now asserts exit 74 for unreadable roots) (`-I` replaced by `-B` with `PYTHONPATH` removed, because `-I`
hides a user-site `cryptography`), and are run by `tests/test_nemesis_wrapper.py`. The round-1 checks were written
for 1.2.1: the wrapper runs them with the 1.2.1 readings as defaults (all pass) and with the 1.3 defaults, where
exactly six fail, each for a 1.3 sentence: old vector 12 (12b replaces it), old vector 20 (amended), M41 (the
unsigned `signature.key_id` no longer names the signer), M59, M60 and F11 (a bad key is `KEY_REJECTED`, not refused
or accepted with a note).

## Mutation battery (`tools/mutate.py`, `tools/mutation_report.py`, `results/mutation*.json`)

### Spot-check of the profile 1.3 changes (`results/mutation13.json`)

The same operators, restricted with `--only` to the sites on lines changed for 1.3 (`check_keyfile` and `verify`;
the CLI excluded): 72 mutants. Suites: the 27 vectors of 1.3, the live record, the 52 own vectors,
`tests/test_profile13.py`, `tests/test_local_blocks.py`, and the alternative readings (`OPTION_SETS` in
`tools/mutate.py`) on the 23 vectors of the 1.2.1 round, the live record and the 52 own vectors. First pass:
67 killed, 5 survivors. One (the tie between `issued_utc` and a covering token, which changes only the label of the
reference) is killed by the unit-test suite; for the other four, three assertions were added to
`tests/test_profile13.py` (the `rejected_keys` detail, the exact 1.2.1 refusal reason for a 31-byte key, a weak key
under `--profile 1.2.1 --ed25519 rfc8032`), and all four are killed. Result: 72/72 killed.

### Full battery (version 0.1.0; not re-run for 0.2.0)

Mutation operators, applied to `war_verify.py` 0.1.0 (SHA-256 560a6200…cb65, the file before the second review
changed one comment and the module docstring) at each site:
- every comparison flipped;
- every `and`/`or` swapped;
- every `not` removed;
- every `raise` and every `.add(...)` statement removed;
- every `if` test forced to False.

The module-level `__main__` guard is excluded. This gives 1073 mutants. Each runs in its own process, writes its
own result file, and has a timeout. A mutant is killed when any compared outcome differs from the original's.

| suites so far | surviving mutants |
|---|---|
| the 23 vectors | 736 |
| + the 43 new vectors | 597 |
| + the generative attack (596 cases) | 555 |
| + unit tests, the alternative readings on all vectors, the review's checks | 359 |
| + `tests/test_local_blocks.py` | 324 |

Of the kills, 23 are by exception and 1 by timeout.

42 of the 43 vectors of 0.1.0 each kill at least one mutant that passes all 23 published vectors; that mutant is a lax
verifier that the vector catches while this verifier agrees. The vector-to-mutant map is in `results/mutation.json`.
omega-08 kills none.

What the 324 survivors are:
- `verify_tsa` (44): pkix checks without a negative case;
- `main` (44): the CLI, tested only through subprocesses;
- `verify` (26): mostly extension-code bookkeeping;
- DER and JSON guards (`_der_tlv` 21, `parse_token` 19, `parse_tstinfo` 16, ...): mostly guards whose removal
  lets a later check refuse the same input with another reason.

They are not proven equivalent. In `_jcs_number`, a boundary test added afterwards (0.5, 1e20) kills 2 of the 11
survivors. From reading the code, the other 9 look unreachable from the parser, but that is not proven.

## New vectors (`vectors/`, CC0)

52 vectors. They are signed with the `omega-test-1` and `omega-test-2` TEST keys, whose private seeds are
published in every vector (never trust them), and are built by `tools/make_vectors.py`. Each `expected` object was
written from the text; the sentence used is in the vector's `reading` field. `expected_extensions` lists this
verifier's own `X_` codes and is not part of the profile. Where this verifier's 1.2.1 reading gives other profile
fields, they are in `expected_1_2_1`.

At 1.3, the `inputs` of omega-01 to omega-43 are unchanged (rebuilt byte for byte). Seven expectations changed, each
with the 1.3 sentence in `reading`:
- omega-11 (signed `receipt.key_id` names the other key): `SIGNATURE_INVALID` and `CHECKER_NOT_SIGNER` (step 2);
- omega-21, omega-24, omega-25 (`issued_utc` 12:00:00, not later than the commitment, is earlier than the covering
  token): `no` and `CRITERIA_COMMITTED_AFTER_CHECK` (step 5, earlier-of);
- omega-27 (identity key signs): `KEY_REJECTED`, `signature_valid` false;
- omega-28, omega-29 (a bad key that signs nothing): the profile fields of a valid record and the local block
  `X_UNUSED_KEY_REJECTED` (previously refused).

Nine vectors were added for the 1.3 rulings: omega-44 (envelope `key_id` differs), omega-45 (signer key of mixed
order), omega-46 to omega-49 (accuracy widening, no accuracy, `ordering` ignored, with `issued_utc` later than the
tokens), omega-50 (widening against `issued_utc`, a reading no published vector pins), omega-51 and omega-52 (stated
`self-checked` against a derived `independent` or `undeclared`).

This verifier agrees with 52/52 under the defaults, and with 52/52 under `--profile 1.2.1` against
`expected_1_2_1` (or `expected` where the readings agree). The lax verifier is wrong on 41/52.
