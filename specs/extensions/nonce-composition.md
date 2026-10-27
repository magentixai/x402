# Extension: nonce composition (`x402-nonce/1`)

**Draft for review.** Proposed by magentixai as the follow-up agreed on x402-foundation/x402#3220 (4 and 5 Oct 2026). Pinned against #3220 at `72c3704`, the derived-nonce construction in #3226, and the x402 `payment-identifier` extension.

## Summary

Several x402 extensions want to bind a value into the one payer-chosen 32-byte slot a payment scheme signs (the EIP-3009 `nonce`, the Permit2 `nonce`, the XRPL `InvoiceID`):

- `authority` (#3220 section 7) writes its binding B there;
- the resource binding (#3226) writes `keccak256(resource || salt)` there.

**#3220 section 7 does not change.** When a mandate is present, the slot is B, as it is today. The other bindings are composed into the one input of B that the payer already chooses freely, the `paymentId`:

```
id        = SHA-256( "x402-nonce/1\n" || JCS(members) )
paymentId = "x402n_" || base64url(id)                       // anchored form, mandate present
slot      = B = SHA-256( "x402-mandate-binding/1\n" || UTF8(mandateDigest || "\n" || paymentId) )
```

Without a mandate, two or more members compose directly: `slot = id` (the flat form). A single binding with no mandate keeps its own value in the slot (the bare form).

**One rule carries the security (R1):** an authority verifier accepts a payment only if the slot equals B. A composition that contains the mandate binding is refused. That is what keeps the chain enforcing #3220's "the same `(mandate, paymentId)` settles at most once" (section 8).

## 1. Motivation

A payment that should carry both a spending mandate and a resource binding today has to choose between them. One tagged derivation over named members lets each extension stay independent, in the same spirit as the offered / required / chosen lane contract.

The obvious design, hashing every member, including the mandate binding, into the slot, has a defect:
- The chain consumes the slot, so it would enforce "at most once" only for the whole combination of members.
- The agent chooses that combination. It could put one B inside two different compositions, get two fresh nonces, and settle one `(mandate, paymentId)` twice.

This document avoids the defect. The slot keeps depending on `(mandate, paymentId)` alone, and the other members go inside the `paymentId`.

## 2. Terminology

- **Slot**: the 32 payer-chosen bytes the scheme's signature covers, decoded from the scheme's encoding (section 7).
- **Member**: a named 32-byte binding value, defined by the extension that owns the name.
- **Opening**: `{ "v": "x402-nonce/1", "members": { <name>: <value>, ... } }`, which discloses the members behind an anchored `paymentId` or a flat slot.
- **Bare form**: the slot is one binding's own value. This is B when a mandate is present, or a single other member when there is none.
- **Anchored form**: a mandate is present, the slot is B, and `paymentId` = `"x402n_"` + base64url(id).
- **Flat form**: no mandate, and the slot is id over two or more members.

The key words MUST, MUST NOT, SHOULD and MAY are to be read as in RFC 2119 and RFC 8174.

## 3. Members

A member name MUST match `^[a-z][a-z0-9-]{0,31}$`. A member value MUST be the string `0x` followed by exactly 64 lowercase hex characters. Values that are not in this form are refused, not normalised.

| Name | Value | Defined by |
|---|---|---|
| `resource` | `keccak256(resource \|\| salt)` | #3226 (its encoding, salt length and salt location are still open there) |
| `entropy` | 32 random bytes | this document; makes an id unpredictable from public inputs |

**R1. `authority` is never a member.** An opening containing a member named `authority` is malformed for every verifier. The mandate binding is always the anchor, never a member (section 5.1).

An opening MAY carry names not in the table. A verifier MUST include them when it recomputes id, and MUST NOT otherwise interpret them. A name enters the table when the extension that defines its value is accepted.

**Only one binding can own the slot's uniqueness.** That follows from there being one nonce. When a mandate is present, it is the anchor. Any other binding that needs "at most once" (an invoice number, for example) is de-duplicated by verifiers, not by the chain.

## 4. Composition

**With a mandate (anchored form):**
1. Collect 1 to 16 members.
2. Compute id = SHA-256(`"x402-nonce/1\n"` || JCS(members)), where JCS is RFC 8785. Every name and value is ASCII, so JCS here is the members sorted by name and serialised with no whitespace.
3. Set `paymentId` = `"x402n_"` || base64url(id), unpadded (49 characters). Carry it as the `payment-identifier` extension's `id`.
4. Derive B from `(mandateDigest, paymentId)` exactly as #3220 section 7 says, and write B into the slot.

**Without a mandate:**
- **Flat form:** with 2 to 16 members, write id into the slot.
- **Bare form:** with exactly one binding, write that binding's own value into the slot. A flat composition of one member is malformed.

In every form, the opening MUST be made available to every party that will verify a member (section 11 names where it travels as open).

**R2. Members are fixed per logical payment.** A client MUST choose the members once (including any `entropy`), save them with the payment, and reuse them on every retry. The `payment-identifier` extension treats one ID as one logical request. Fresh members on a retry would produce a new `paymentId`, and so a second charge.

**R3. paymentId grammar.** A `paymentId` used with a mandate SHOULD match `^[A-Za-z0-9_-]{16,64}$`. That is where #3220's grammar (`^[A-Za-z0-9._~-]{1,64}$`) and the `payment-identifier` extension's (`^[a-zA-Z0-9_-]+$`, 16 to 128 characters) overlap. The anchored form always matches it. #3220's own vector `paymentId`, `pay-001`, does not: it is 7 characters, so `payment-identifier` would refuse it.

**Worked example** (vector `nc-03`), with #3220's model A mandate:

```
members   = { "resource": "0x1be364d4cb5cb9bad2a55c962bee25d671c522d1f498e323b51d075786f2c675" }
paymentId = x402n_EblQwucrBggbWFTi-D1L5BZeRVl_Utg5OHNIE1Yeg3Y
slot (B)  = 0xb9b0d94d4986f010b43c9fb8075dbced28a218986602b45736208a4848d75e59
```

## 5. Verification

Every verifier reads the slot from the settled artifact (the signed authorization or the transaction), never from a presented field, as #3220 section 7 already requires. It then decodes the slot to 32 bytes N (section 7). A slot outside its scheme's encoding is malformed.

### 5.1 The authority verifier

The authority verifier has the mandate and the payment's `paymentId`. It computes B as #3220 section 7 says, then:

1. If N = B, the verdict is `bound`.
2. Otherwise the verdict is `binding_mismatch` (contradicted).
   - When the presented opening contains an `authority` member and recomputes to N, a verifier MAY report the more specific `composed_authority`. That is the flat attack R1 exists to refuse (vector `nc-08`).

The authority verifier never needs the opening. A lost or withheld opening affects the other members' verdicts, never the mandate's.

### 5.2 A member verifier

A verifier for member `m` computes `m`'s expected value E from its own inputs, by the rules of the extension that defines `m`. Then:

1. If N = E, the verdict is `bound` (bare form).
2. If no opening is available, the verdict is `indeterminate`.
3. If the opening is not well formed, the verdict is `malformed_opening`. Well formed means all of these:
   - its only members are `v` and `members`;
   - `v` is `x402-nonce/1`;
   - `members` has 1 to 16 entries, and none is named `authority`;
   - every name and value matches section 3.
4. Compute id over opening.members, then:
   - **(a) Flat form.** If id = N: if the opening has fewer than 2 members, the verdict is `malformed_opening`; otherwise continue to step 5.
   - **(b) Anchored form.** Otherwise, if a mandate context `(mandateDigest, paymentId)` is presented, `paymentId` = `"x402n_"` || base64url(id), and N = B over that context: continue to step 5.
   - **(c) Otherwise** the verdict is `opening_mismatch`.
5. If `m` is not in the opening, the verdict is `member_absent`.
6. If opening.members[m] ≠ E, the verdict is `member_mismatch`.
7. Otherwise the verdict is `bound`.

A member verifier that checks the anchored form learns the `mandateDigest` (section 10).

A JSON parser that accepts duplicate member names MUST NOT be used to read an opening.

## 6. Verdicts

| Verdict | Verifier | Meaning | Four-state reading |
|---|---|---|---|
| `bound` | both | The signed slot commits to E | verified |
| `binding_mismatch` | authority | A mandate is presented, but the slot is not its B | contradicted |
| `composed_authority` | authority | As `binding_mismatch`, diagnosed as the flat attack | contradicted |
| `opening_mismatch` | member | The opening is not what the slot or `paymentId` commits to | contradicted |
| `member_absent` | member | The commitment does not include `m` | contradicted |
| `member_mismatch` | member | The commitment holds a different value for `m` | contradicted |
| `malformed_opening` | member | The presented opening is not valid | contradicted |
| `indeterminate` | member | No opening is available and the slot is not E | indeterminate |

`indeterminate` is a first-class verdict, as #3226's second and third caveats require. Every payment already on chain has a random nonce, and a slot without an opening is not evidence of wrongdoing.

`binding_mismatch` is different. It applies only when a mandate is presented for the payment, and #3220 section 7 already says the slot MUST equal B.

## 7. Scheme encodings

These are the same as #3220 section 7, applied to the slot value (B, id, or a bare member):

| Scheme | Slot | Encoding |
|---|---|---|
| EIP-3009 `transferWithAuthorization` | `nonce` (bytes32) | `0x` + lowercase hex |
| Permit2 `PermitTransferFrom` | `nonce` (uint256) | big-endian unsigned integer, decimal, no leading zeros |
| XRPL `Payment` | `InvoiceID` | uppercase hex |

Vectors `nc-03` to `nc-05` give one anchored payment in all three encodings.

## 8. Effect on at-most-once

- **Varying the members gives a new `paymentId`.** That is a new payment, which the spend log records and the cap counts.
- **Reusing a `paymentId` reproduces B.** EIP-3009 and Permit2 consume the slot, so they refuse to settle it twice, exactly as today.
- **R1 refuses the one construction that escapes this:** B composed alongside other members, which gives two fresh slots for one `(mandate, paymentId)`.

Vector `nc-19` shows all three: retries are equal, variants differ, and the flat attack is refused.

**What this does not change:**
- **XRPL** still does not enforce `InvoiceID` uniqueness, so #3220's de-duplication rule for XRPL stands.
- **An EVM nonce is unique per token contract per chain.** "At most once" is complete only if the mandate's `asset` names the chain and contract. This document supports making `asset` CAIP-19, as StratedgeWorkflowSystems proposed on #3220 (4 Oct, point 1).
- **Schemes with no payer-chosen 32-byte slot** (for example SVM) are out of scope here, as they are in #3220.

## 9. Changes this needs elsewhere

- **#3220 section 7: none to the derivation.**
  - Add R1 ("the slot MUST equal B; a composed slot is not a binding") and R3.
  - Define `x402n_` `paymentId` values by reference to this document.
- **#3220 section 19 (carriage):** names where the opening travels. Authority verification does not need it.
- **#3376 `x402_evc.payment`:** gains an optional `nonce_opening`, copied verbatim. `binding_slot` and `payment_id` are unchanged.
- **`payment-identifier`:** nothing. An `x402n_` value is a valid ID. Clients follow R2.
- **#3226:** fixes the `resource` member's encoding and salt location (its own open items), and its verifier handles the anchored form.

## 10. Security and privacy considerations

1. **Binding strength.** Two openings that give one `paymentId` or slot require a SHA-256 collision. Claiming another member set for an existing one requires a second preimage. Each member proves what its own extension proves, and nothing more. A bound resource member binds what the payer committed to, not what was delivered (#3226's first caveat).
2. **Illustrative `resource` encoding.** The vectors use keccak256(UTF8(resource) || salt) with a 32-byte salt. #3226 has not fixed this, and the vectors will be regenerated when it does.
3. **Disclosure.**
   - An opening shows every member's value to its verifiers.
   - A member verifier checking the anchored form also learns the `mandateDigest`, which links payments made under one mandate. The payee usually sees the mandate anyway, so in practice this affects third parties that verify only a member.
   - A verifier can test guesses of low-entropy inputs, such as a resource URL when the salt is published.
   - `entropy` stops id being predicted from public inputs. It does not hide members once the opening is shown.
4. **Unknown members** are hashed, not interpreted. A verifier MUST NOT treat a name it does not know as meaningful.
5. **Coupling.** A member verifier checking the anchored form needs #3220's binding formula (one hash). The dependency runs one way: the authority verifier needs nothing from members.

## 11. Open questions for the group

1. **Where the opening travels** (#3220 section 19, #3376): in the payload, in a receipt, or both.
2. **Selective disclosure.** A Merkle variant (one leaf per member, the root as id) would let a verifier see only its own member, at the cost of a proof per member. Is that worth a `/2`?
3. **The `entropy` member.** Whether it should be RECOMMENDED by default.
4. **Registry home.** Where the member-name table lives, and who reviews additions.
5. **R3 as a MUST.** Whether R3 should become a MUST in #3220 itself, which would mean regenerating its `pay-001` vectors.

## 12. Constants

| Item | Value |
|---|---|
| Version / domain-separation tag | `x402-nonce/1` / `x402-nonce/1\n` |
| Anchored `paymentId` | `x402n_` + base64url(id), unpadded, 49 characters |
| Member name | `^[a-z][a-z0-9-]{0,31}$`, never `authority` |
| Member value | `^0x[0-9a-f]{64}$` |
| Members | anchored 1 to 16; flat 2 to 16 |
| paymentId with a mandate (R3) | `^[A-Za-z0-9_-]{16,64}$` (SHOULD) |
| Hash / canonicalisation | SHA-256 / RFC 8785 (JCS) |

## 13. Conformance vectors

`nonce-composition-vectors.json` has 19 payment vectors and one reuse vector, giving 58 checks. They cover every verdict, R1 (`nc-08`), R3 (`nc-01`), and the at-most-once argument (`nc-19`).

- `nonce-composition-tools/generate.py` (development tool; needs `pycryptodome`) regenerates the file byte for byte.
- `nonce-composition-tools/verify.py` uses the Python standard library only, with its own Keccak-256.

Author run: 58/58.
- The verifier's Keccak-256 agrees with pycryptodome, and its JCS agrees with the `jcs` package.
- `nc-01` reproduces #3220's published model A binding exactly.
- Seven deliberate faults were each caught by at least one check:
  - dropping R1 from the opening grammar;
  - dropping the R1 diagnosis;
  - accepting a one-member flat form;
  - skipping the anchored slot check (caught by `nc-20`);
  - skipping the anchored `paymentId` check;
  - stripping the `sha256:` prefix;
  - normalising case.

These are author runs, and they need an independent rerun.

## Credits

- The binding B and the slot encodings: whawk46 (#3220).
- The derived resource nonce and its three caveats: Circadian-agent (#3226), who asks to be credited as an autonomous AI agent operation.
- The `x402_evc.payment` carriage: saneGuy (#3376).
- The tagged-derivation idea was agreed in principle by whawk46 on #3220 (5 Oct 2026). The anchored form replaces the flat form proposed there, for the reason in section 1.

Disclosure per CONTRIBUTING: drafted with AI assistance, to be reviewed and posted by magentixai.
