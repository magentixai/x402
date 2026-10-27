#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate nonce-composition-vectors.json for the x402 nonce composition draft (x402-nonce/1), anchored design.

Development tool. Needs pycryptodome (keccak-256, for the illustrative #3226 resource member only).

    python generate.py            # writes ../nonce-composition-vectors.json

With a mandate, the slot is always #3220's B; the other members are composed into the paymentId:
    id        = SHA-256("x402-nonce/1\\n" || JCS(members))
    paymentId = "x402n_" + base64url(id)
Without a mandate, two or more members compose flat: slot = id.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from Crypto.Hash import keccak

OUT = Path(__file__).resolve().parent.parent / "nonce-composition-vectors.json"

COMPOSE_TAG = b"x402-nonce/1\n"
BINDING_TAG = b"x402-mandate-binding/1\n"

# #3220 model A vector mandate digest (authority-vectors.json at 72c3704)
MANDATE_DIGEST = "sha256:445fed871d7c43d2b775e68124103c77646fc0f096fb42c9ea3d9f00c960ca05"
RESOURCE = "https://api.example.com/v1/rows/42"
OTHER_RESOURCE = "https://api.example.com/v1/rows/43"


def jcs(v) -> bytes:
    # Scope of this draft: ASCII member names, string values only, so sorted compact JSON is RFC 8785.
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def hx(b: bytes) -> str:
    return "0x" + b.hex()


def label_bytes(label: str) -> bytes:
    return hashlib.sha256(("x402-nonce-composition-vectors:" + label).encode("utf-8")).digest()


def authority_b(payment_id: str) -> str:
    return hx(hashlib.sha256(BINDING_TAG + (MANDATE_DIGEST + "\n" + payment_id).encode("utf-8")).digest())


def resource_r(resource: str, salt: bytes) -> str:
    # Illustrative encoding of #3226: keccak256(UTF8(resource) || salt), salt 32 bytes. #3226 has not fixed this.
    k = keccak.new(digest_bits=256)
    k.update(resource.encode("utf-8") + salt)
    return hx(k.digest())


def compose_id(members: dict) -> bytes:
    return hashlib.sha256(COMPOSE_TAG + jcs(members)).digest()


def anchored_payment_id(members: dict) -> str:
    return "x402n_" + base64.urlsafe_b64encode(compose_id(members)).rstrip(b"=").decode("ascii")


def slot(scheme: str, n_hex: str) -> str:
    raw = bytes.fromhex(n_hex[2:])
    if scheme == "eip3009":
        return n_hex
    if scheme == "permit2":
        return str(int.from_bytes(raw, "big"))
    if scheme == "xrpl":
        return raw.hex().upper()
    raise ValueError(scheme)


def main() -> None:
    salt, salt2 = label_bytes("salt-1"), label_bytes("salt-2")
    R = resource_r(RESOURCE, salt)
    R_other = resource_r(OTHER_RESOURCE, salt2)
    E = hx(label_bytes("entropy-1"))
    X = hx(label_bytes("x-example"))
    res_in = {"resource": RESOURCE, "salt": hx(salt)}

    def op(members, v="x402-nonce/1"):
        return {"v": v, "members": members}

    def mandate(pid):
        return {"mandateDigest": MANDATE_DIGEST, "paymentId": pid}

    def vec(id_, desc, scheme, nonce_hex, opening, mctx, expect, rin=res_in):
        return {"id": id_, "description": desc, "scheme": scheme, "slot": slot(scheme, nonce_hex),
                "opening": opening, "mandate_context": mctx, "resource_inputs": rin, "expect": expect}

    m_pair = {"resource": R}
    pid_pair = anchored_payment_id(m_pair)
    B_pair = authority_b(pid_pair)
    m_ent = {"entropy": E, "resource": R}
    pid_ent = anchored_payment_id(m_ent)
    m_unk = {"resource": R, "x-example": X}
    pid_unk = anchored_payment_id(m_unk)
    m_only_ent = {"entropy": E}
    pid_only_ent = anchored_payment_id(m_only_ent)
    m_wrong = {"resource": R_other}
    pid_wrong = anchored_payment_id(m_wrong)
    plain_pid = "pay_7d5d747be160e280504c099d984bcfe0"   # payment-identifier style, decomposes to nothing
    B_plain = authority_b(plain_pid)
    B_001 = authority_b("pay-001")
    flat_attack_members = {"authority": authority_b(plain_pid), "resource": R}

    vectors = [
        vec("nc-01-bare-authority-3220", "Mandate only, paymentId pay-001: the slot is #3220's published model A B. "
            "pay-001 is inside #3220's grammar but under the payment-identifier extension's 16-character minimum (R3).",
            "eip3009", B_001, None, mandate("pay-001"), {"authority": "bound", "resource": "indeterminate", "r3": False}),
        vec("nc-02-bare-resource", "No mandate, resource binding alone: the slot is the #3226 value exactly.",
            "eip3009", R, None, None, {"resource": "bound"}),
        vec("nc-03-anchored-eip3009", "Mandate plus resource: slot = B, the resource member is composed into the paymentId.",
            "eip3009", B_pair, op(m_pair), mandate(pid_pair), {"authority": "bound", "resource": "bound", "r3": True}),
        vec("nc-04-anchored-permit2", "Same payment, Permit2 encoding (big-endian uint256, decimal).",
            "permit2", B_pair, op(m_pair), mandate(pid_pair), {"authority": "bound", "resource": "bound", "r3": True}),
        vec("nc-05-anchored-xrpl", "Same payment, XRPL InvoiceID encoding (uppercase hex).",
            "xrpl", B_pair, op(m_pair), mandate(pid_pair), {"authority": "bound", "resource": "bound", "r3": True}),
        vec("nc-06-anchored-with-entropy", "Anchored resource and entropy members.",
            "eip3009", authority_b(pid_ent), op(m_ent), mandate(pid_ent), {"authority": "bound", "resource": "bound", "r3": True}),
        vec("nc-07-anchored-unknown-member", "An unregistered member is opaque to this verifier but still hashed.",
            "eip3009", authority_b(pid_unk), op(m_unk), mandate(pid_unk), {"authority": "bound", "resource": "bound", "r3": True}),
        vec("nc-08-flat-attack-refused-R1", "The agent composes the mandate binding flat with a resource member. "
            "R1: the authority verifier accepts only slot = B, so this is refused; an opening holding an authority "
            "member is malformed for every verifier.",
            "eip3009", hx(compose_id(flat_attack_members)), op(flat_attack_members), mandate(plain_pid),
            {"authority": "composed_authority", "resource": "malformed_opening", "r3": True}),
        vec("nc-09-anchored-opening-altered", "Opening presented with another resource value than the paymentId commits to. "
            "The authority check does not read the opening and still binds.",
            "eip3009", B_pair, op({"resource": R_other}), mandate(pid_pair),
            {"authority": "bound", "resource": "opening_mismatch", "r3": True}),
        vec("nc-10-plain-payment-id", "A plain random paymentId with an opening presented beside it: the paymentId does not "
            "decompose to that opening.",
            "eip3009", B_plain, op(m_pair), mandate(plain_pid), {"authority": "bound", "resource": "opening_mismatch", "r3": True}),
        vec("nc-11-anchored-member-mismatch", "The paymentId composes a resource member for another resource.",
            "eip3009", authority_b(pid_wrong), op(m_wrong), mandate(pid_wrong),
            {"authority": "bound", "resource": "member_mismatch", "r3": True}),
        vec("nc-12-anchored-member-absent", "The paymentId composes only an entropy member.",
            "eip3009", authority_b(pid_only_ent), op(m_only_ent), mandate(pid_only_ent),
            {"authority": "bound", "resource": "member_absent", "r3": True}),
        vec("nc-13-flat-no-mandate", "No mandate: resource and entropy composed flat into the slot.",
            "eip3009", hx(compose_id(m_ent)), op(m_ent), None, {"resource": "bound"}),
        vec("nc-14-flat-single-member", "A flat composition of one member is malformed: one member uses the bare form.",
            "eip3009", hx(compose_id(m_pair)), op(m_pair), None, {"resource": "malformed_opening"}),
        vec("nc-15-uppercase-member-value", "Member values are 0x plus 64 lowercase hex; uppercase is refused, not normalised.",
            "eip3009", hx(compose_id({"entropy": E, "resource": R.upper().replace("0X", "0x")})),
            op({"entropy": E, "resource": R.upper().replace("0X", "0x")}), None, {"resource": "malformed_opening"}),
        vec("nc-16-wrong-version", "Opening carries an unregistered version string.",
            "eip3009", B_pair, op(m_pair, v="x402-nonce/2"), mandate(pid_pair),
            {"authority": "bound", "resource": "malformed_opening", "r3": True}),
        vec("nc-17-opening-withheld", "Anchored payment, opening not presented: resource is indeterminate; authority binds.",
            "eip3009", B_pair, None, mandate(pid_pair), {"authority": "bound", "resource": "indeterminate", "r3": True}),
        vec("nc-18-random-nonce-with-mandate", "A mandate is presented but the slot is a random nonce: #3220 section 7 "
            "binding mismatch; the resource binding is indeterminate.",
            "eip3009", hx(label_bytes("legacy-random")), None, mandate(plain_pid),
            {"authority": "binding_mismatch", "resource": "indeterminate", "r3": True}),
        vec("nc-20-anchored-id-not-signed", "The paymentId decomposes to the opening, but the slot is not B for it: the "
            "resource commitment never entered the signed slot.",
            "eip3009", hx(label_bytes("legacy-random")), op(m_pair), mandate(pid_pair),
            {"authority": "binding_mismatch", "resource": "opening_mismatch", "r3": True}),
    ]

    # Reuse checks. Anchored: varying the members changes the paymentId (a new, logged payment); reusing a paymentId
    # reproduces the same slot, which EIP-3009 and Permit2 refuse to settle twice. Flat (the nc-08 attack): one B in
    # two compositions gives two fresh slots, which is why R1 refuses flat compositions holding an authority member.
    m_b = {"resource": R_other}
    reuse = {
        "id": "nc-19-reuse",
        "description": "Same mandate. Anchored payments a and b vary the resource member; a2 retries a with the same members.",
        "anchored": {
            "a": {"members": m_pair, "paymentId": pid_pair, "slot": B_pair},
            "a2": {"members": m_pair, "paymentId": anchored_payment_id(m_pair), "slot": authority_b(anchored_payment_id(m_pair))},
            "b": {"members": m_b, "paymentId": anchored_payment_id(m_b), "slot": authority_b(anchored_payment_id(m_b))},
        },
        "flat_attack": [
            hx(compose_id({"authority": authority_b(plain_pid), "resource": R})),
            hx(compose_id({"authority": authority_b(plain_pid), "resource": R_other})),
        ],
        "expect": {"a_equals_a2": True, "a_differs_b": True, "paymentIds_differ_ab": True,
                   "flat_slots_differ": True, "flat_each_authority": "composed_authority"},
        "flat_mandate_context": mandate(plain_pid),
        "flat_resource_inputs": [res_in, {"resource": OTHER_RESOURCE, "salt": hx(salt2)}],
    }

    doc = {
        "version": "x402-nonce/1",
        "status": "DRAFT for review",
        "constants": {"compose_tag": "x402-nonce/1\\n", "binding_tag": "x402-mandate-binding/1\\n",
                      "anchored_payment_id_prefix": "x402n_"},
        "notes": [
            "authority = B per x402 PR #3220 section 7 at 72c3704; nc-01 equals that PR's published model A value.",
            "resource = keccak256(UTF8(resource) || salt) with a 32-byte salt. ILLUSTRATIVE: issue #3226 has not fixed "
            "the encoding, the salt length or where the salt is published.",
            "r3 = the paymentId matches ^[A-Za-z0-9_-]{16,64}$, the overlap of #3220's grammar and the payment-identifier "
            "extension's. Informative: it is a proposed tightening, not part of either text yet.",
            "All other bytes derive from SHA-256('x402-nonce-composition-vectors:' + label). Test values; they hold nothing.",
        ],
        "verdicts": {
            "authority": ["bound", "binding_mismatch", "composed_authority"],
            "resource": ["bound", "member_absent", "member_mismatch", "opening_mismatch", "malformed_opening", "indeterminate"],
        },
        "vectors": vectors,
        "reuse_vectors": [reuse],
    }
    OUT.write_bytes((json.dumps(doc, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))
    print("wrote", OUT)
    print("anchored paymentId", pid_pair, "slot B", B_pair)


if __name__ == "__main__":
    main()
