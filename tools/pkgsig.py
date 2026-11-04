#!/usr/bin/env python3
"""PS4 PKG header signature.

An RSA-2048 public-key operation over SHA-256 of header[0:0x1000], padded with
bytes drawn from a Mersenne Twister seeded by SHA256(SHA256(modulus || hash)).
Only the public modulus is required.
"""
import hashlib
import struct

N = 624
M = 397
DEFAULT_SEED = 0x12BD6AA
MATRIX_A = 0x9908B0DF
UPPER_MASK = 0x80000000
LOWER_MASK = 0x7FFFFFFF
C1 = 0x6C078965
C2 = 0x19660D
C3 = 0x5D588B65
C4 = 0x9D2C5680
C5 = 0xEFC60000
MASK32 = 0xFFFFFFFF


class MersenneTwister:
    def __init__(self, seed):
        self.mt = [0] * N
        self.mt[0] = DEFAULT_SEED
        for i in range(1, N):
            prev = self.mt[i - 1]
            self.mt[i] = (i + C1 * (prev ^ (prev >> 30))) & MASK32
        self.mti = N

        if isinstance(seed, (list, tuple)):
            state_idx, seed_idx = 1, 0
            for _ in range(max(N, len(seed)), 0, -1):
                prev = self.mt[state_idx - 1]
                self.mt[state_idx] = (
                    (self.mt[state_idx] ^ ((prev ^ (prev >> 30)) * C2))
                    + seed[seed_idx] + seed_idx) & MASK32
                state_idx += 1
                seed_idx += 1
                if state_idx >= N:
                    self.mt[0] = self.mt[N - 1]
                    state_idx = 1
                if seed_idx >= len(seed):
                    seed_idx = 0
            for _ in range(N - 1):
                prev = self.mt[state_idx - 1]
                self.mt[state_idx] = (
                    (self.mt[state_idx] ^ ((prev ^ (prev >> 30)) * C3))
                    - state_idx) & MASK32
                state_idx += 1
                if state_idx >= N:
                    self.mt[0] = self.mt[N - 1]
                    state_idx = 1
            self.mt[0] = 1 << 31

    def int32(self):
        if self.mti >= N:
            for kk in range(N - M):
                y = (self.mt[kk] & UPPER_MASK) | (self.mt[kk + 1] & LOWER_MASK)
                self.mt[kk] = self.mt[kk + M] ^ (y >> 1) ^ (MATRIX_A if y & 1 else 0)
            for kk in range(N - M, N - 1):
                y = (self.mt[kk] & UPPER_MASK) | (self.mt[kk + 1] & LOWER_MASK)
                self.mt[kk] = (self.mt[kk + M - N] ^ (y >> 1)
                               ^ (MATRIX_A if y & 1 else 0))
            y = (self.mt[N - 1] & UPPER_MASK) | (self.mt[0] & LOWER_MASK)
            self.mt[N - 1] = self.mt[M - 1] ^ (y >> 1) ^ (MATRIX_A if y & 1 else 0)
            self.mti = 0
        y = self.mt[self.mti]
        self.mti += 1
        y ^= y >> 11
        y = (y ^ ((y << 7) & C4)) & MASK32
        y = (y ^ ((y << 15) & C5)) & MASK32
        y ^= y >> 18
        return y & MASK32


def sign(modulus: bytes, digest: bytes) -> bytes:
    seed_hash = hashlib.sha256(hashlib.sha256(modulus + digest).digest()).digest()
    seed = list(struct.unpack(">8I", seed_hash))
    mt = MersenneTwister(seed)

    padded = bytearray(256)
    padded[0] = 0
    padded[1] = 2
    padded[223] = 0
    padded[224:256] = digest

    k = 2
    while k < 223:
        block = b"".join(struct.pack(">I", mt.int32()) for _ in range(12))
        for r in hashlib.sha256(block).digest():
            if k >= 223:
                break
            if r != 0:
                padded[k] = r
                k += 1

    n = int.from_bytes(modulus, "big")
    c = pow(int.from_bytes(bytes(padded), "big"), 65537, n)
    return c.to_bytes(256, "big")
