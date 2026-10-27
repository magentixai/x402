#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verifier for the x402 nonce composition draft (x402-nonce/1). Python standard library only, no network.

    python verify.py [../nonce-composition-vectors.json]

Anchored design. The authority verifier (section 5.1 of the draft) accepts only slot = B, recomputed from #3220
section 7 (rule R1). The resource verifier (section 5.2) accepts the bare form, a flat composition (no mandate), or an
anchored paymentId (mandate present, slot = B over "x402n_" + base64url(id)). The resource value uses the
illustrative #3226 encoding, with this file's own Keccak-256 so it shares no code with the generator.

Exit 0 when every verdict matches, 1 otherwise.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import sys
from pathlib import Path

COMPOSE_TAG = b"x402-nonce/1\n"
BINDING_TAG = b"x402-mandate-binding/1\n"
VERSION = "x402-nonce/1"
NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
VALUE_RE = re.compile(r"^0x[0-9a-f]{64}$")
MAX_MEMBERS = 16
R3_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")


# ---------- Keccak-256 (original Keccak padding 0x01, as Ethereum uses; not SHA3-256)

_RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B,
       0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088,
       0x0000000080008009, 0x000000008000000A, 0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
       0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
       0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_M = (1 << 64) - 1


def _rol(v, n):
    return ((v << n) | (v >> (64 - n))) & _M if n else v


def _f(a):
    for rc in _RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rol(a[x][y], _ROT[x][y])
        a = [[b[x][y] ^ (~b[(x + 1) % 5][y] & b[(x + 2) % 5][y]) for y in range(5)] for x in range(5)]
        a[0][0] ^= rc
    return a


def keccak256(data: bytes) -> bytes:
    rate = 136
    p = bytearray(data) + b"\x01" + b"\x00" * ((-len(data) - 1) % rate)
    p[-1] |= 0x80
    a = [[0] * 5 for _ in range(5)]
    for off in range(0, len(p), rate):
        for i in range(rate // 8):
            a[i % 5][i // 5] ^= int.from_bytes(p[off + 8 * i: off + 8 * i + 8], "little")
        a = _f(a)
    return b"".join(a[i % 5][i // 5].to_bytes(8, "little") for i in range(4))


# ---------- helpers

def jcs(v) -> bytes:
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def decode_slot(scheme: str, s: str) -> bytes:
    if scheme == "eip3009" and re.fullmatch(r"0x[0-9a-f]{64}", s):
        return bytes.fromhex(s[2:])
    if scheme == "permit2" and re.fullmatch(r"0|[1-9][0-9]{0,77}", s) and int(s) < 2 ** 256:
        return int(s).to_bytes(32, "big")
    if scheme == "xrpl" and re.fullmatch(r"[0-9A-F]{64}", s):
        return bytes.fromhex(s)
    raise ValueError("slot not in its scheme's encoding")


def binding_b(ctx: dict) -> bytes:
    return hashlib.sha256(BINDING_TAG + (ctx["mandateDigest"] + "\n" + ctx["paymentId"]).encode("utf-8")).digest()


def compose_id(members: dict) -> bytes:
    return hashlib.sha256(COMPOSE_TAG + jcs(members)).digest()


def opening_ok(op) -> bool:
    """Grammar only: closed object, registered version, 1 to 16 members, names and values in form, no authority (R1)."""
    if not isinstance(op, dict) or set(op) != {"v", "members"} or op["v"] != VERSION:
        return False
    m = op["members"]
    if not isinstance(m, dict) or not 1 <= len(m) <= MAX_MEMBERS or "authority" in m:
        return False
    return all(NAME_RE.match(k) and isinstance(x, str) and VALUE_RE.match(x) for k, x in m.items())


def r3(payment_id: str) -> bool:
    return bool(R3_RE.match(payment_id))


# ---------- section 5.1: the authority verifier

def authority_verdict(scheme: str, slot: str, opening, ctx: dict) -> str:
    n = decode_slot(scheme, slot)
    if n == binding_b(ctx):
        return "bound"
    # R1. Diagnose the flat attack specifically; both outcomes are a refusal.
    if isinstance(opening, dict) and isinstance(opening.get("members"), dict) and "authority" in opening["members"]             and compose_id(opening["members"]) == n:
        return "composed_authority"
    return "binding_mismatch"


# ---------- section 5.2: a member verifier (here, resource)

def member_verdict(name: str, expected: bytes, scheme: str, slot: str, opening, ctx) -> str:
    n = decode_slot(scheme, slot)
    if n == expected:
        return "bound"
    if opening is None:
        return "indeterminate"
    if not opening_ok(opening):
        return "malformed_opening"
    members = opening["members"]
    cid = compose_id(members)
    if cid == n:
        if len(members) < 2:
            return "malformed_opening"
    elif not (ctx and ctx["paymentId"] == "x402n_" + b64u(cid) and n == binding_b(ctx)):
        return "opening_mismatch"
    if name not in members:
        return "member_absent"
    if members[name] != "0x" + expected.hex():
        return "member_mismatch"
    return "bound"


def resource_value(rin: dict) -> bytes:
    return keccak256(rin["resource"].encode("utf-8") + bytes.fromhex(rin["salt"][2:]))


def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent / "nonce-composition-vectors.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    fails = total = 0

    def check(vid, what, got, want):
        nonlocal fails, total
        total += 1
        fails += got != want
        print("%-4s %-34s %-9s %s" % ("ok" if got == want else "FAIL", vid, what, got))

    for v in doc["vectors"]:
        ctx, exp = v["mandate_context"], v["expect"]
        if "authority" in exp:
            check(v["id"], "authority", authority_verdict(v["scheme"], v["slot"], v["opening"], ctx), exp["authority"])
        if "resource" in exp:
            got = member_verdict("resource", resource_value(v["resource_inputs"]), v["scheme"], v["slot"], v["opening"], ctx)
            check(v["id"], "resource", got, exp["resource"])
        if "r3" in exp:
            check(v["id"], "r3", r3(ctx["paymentId"]), exp["r3"])

    for d in doc["reuse_vectors"]:
        a = d["anchored"]
        for k, p in a.items():
            # each anchored payment's paymentId and slot recompute from its members
            ok = p["paymentId"] == "x402n_" + b64u(compose_id(p["members"])) and                 bytes.fromhex(p["slot"][2:]) == binding_b({"mandateDigest": d["flat_mandate_context"]["mandateDigest"],
                                                           "paymentId": p["paymentId"]})
            check(d["id"], "recompute " + k, ok, True)
        e = d["expect"]
        check(d["id"], "a == a2", a["a"]["slot"] == a["a2"]["slot"], e["a_equals_a2"])
        check(d["id"], "a != b", a["a"]["slot"] != a["b"]["slot"], e["a_differs_b"])
        check(d["id"], "pid a != b", a["a"]["paymentId"] != a["b"]["paymentId"], e["paymentIds_differ_ab"])
        fa = d["flat_attack"]
        check(d["id"], "flat differ", fa[0] != fa[1], e["flat_slots_differ"])
        for s, (u, salt) in zip(fa, [(x["resource"], x["salt"]) for x in d["flat_resource_inputs"]]):
            op = {"v": VERSION, "members": {"authority": "0x" + binding_b(d["flat_mandate_context"]).hex(),
                                            "resource": "0x" + resource_value({"resource": u, "salt": salt}).hex()}}
            check(d["id"], "flat authority", authority_verdict("eip3009", s, op, d["flat_mandate_context"]),
                  e["flat_each_authority"])

    print("%d/%d checks match" % (total - fails, total))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
