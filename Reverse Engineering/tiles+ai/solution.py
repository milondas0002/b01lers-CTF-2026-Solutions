#!/usr/bin/env python3
"""
Deterministic solver for the b01lers CTF rev challenge "tiles + ai".

It reconstructs the AMX checker semantics from static tables in ./chall,
performs BFS in the valid-state manifold, and prints 3 accepted round inputs.

Requirements:
  pip install numpy
"""

from __future__ import annotations

from collections import deque
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np

BIN_PATH = Path("chall")
BASE = 0x400000

# Table ranges from static analysis.
A_VA, A_SZ = 0x409000, 0x1000  # 16 blocks, each 0x100
B_VA, B_SZ = 0x40A000, 0x1000  # 16 blocks, each 0x100
C_VA, C_SZ = 0x40B000, 0x4800  # 2*4*3*3 blocks, each 0x100
R_VA, R_SZ = 0x40F800, 0x0900  # 3 round init states, each 0x300

HEX = "0123456789abcdef"
ALPHABET = [(x, y) for x in range(16) for y in range(4)]


def sl(binary: bytes, va: int, sz: int) -> bytes:
    off = va - BASE
    return binary[off : off + sz]


def as_i8(a_u8: np.ndarray) -> np.ndarray:
    return a_u8.view(np.int8)


def trunc_i32_to_u8(m_i32: np.ndarray) -> np.ndarray:
    # vpmovdb behavior: keep low 8 bits.
    return (m_i32.astype(np.int64) & 0xFF).astype(np.uint8)


def repack_16x16_to_tile4x64(src_u8: np.ndarray) -> np.ndarray:
    """
    Mirrors the byte-shuffle loop at 0x4016a0:
    16x16 bytes -> 4x64 tile-memory layout.
    """
    dst = np.zeros((4, 64), dtype=np.uint8)
    for i in range(16):
        dst[i // 4, (i & 3) :: 4] = src_u8[i]
    return dst


def tdpbssd(dst_i32: np.ndarray, src1_u8_16x16: np.ndarray, src2_u8_4x64: np.ndarray) -> np.ndarray:
    """
    Emulate AMX tdpbssd over configured tile shapes:
      src1: 16x16 int8
      src2: 4x64 int8 (interpreted as [k=4][n=16][4 bytes])
      dst : 16x16 int32 accumulate
    """
    s1 = as_i8(src1_u8_16x16).astype(np.int32).reshape(16, 4, 4)
    s2 = as_i8(src2_u8_4x64).astype(np.int32).reshape(4, 16, 4)
    prod = np.einsum("mkl,knl->mn", s1, s2, dtype=np.int64)
    out = (dst_i32.astype(np.int64) + prod) & 0xFFFFFFFF
    return out.astype(np.uint32).view(np.int32)


class Solver:
    def __init__(self, binary: bytes) -> None:
        a_bytes = sl(binary, A_VA, A_SZ)
        b_bytes = sl(binary, B_VA, B_SZ)
        c_bytes = sl(binary, C_VA, C_SZ)
        r_bytes = sl(binary, R_VA, R_SZ)

        self.A = [
            np.frombuffer(a_bytes[i * 0x100 : (i + 1) * 0x100], dtype=np.uint8).reshape(4, 64).copy()
            for i in range(16)
        ]
        self.B = [
            np.frombuffer(b_bytes[i * 0x100 : (i + 1) * 0x100], dtype=np.uint8).reshape(4, 64).copy()
            for i in range(16)
        ]
        self.R = [
            [
                np.frombuffer(
                    r_bytes[r * 0x300 + blk * 0x100 : r * 0x300 + (blk + 1) * 0x100],
                    dtype=np.uint8,
                )
                .reshape(16, 16)
                .copy()
                for blk in range(3)
            ]
            for r in range(3)
        ]

        self.C: List[List[List[List[np.ndarray]]]] = [
            [[[None for _ in range(3)] for _ in range(3)] for _ in range(4)] for _ in range(2)
        ]
        for h in range(2):
            for y in range(4):
                for rbp in range(3):
                    for rcx in range(3):
                        off = h * 0x2400 + y * 0x900 + (rcx + 3 * rbp) * 0x100
                        self.C[h][y][rbp][rcx] = (
                            np.frombuffer(c_bytes[off : off + 0x100], dtype=np.uint8).reshape(16, 16).copy()
                        )

    @staticmethod
    def key(state: List[np.ndarray]) -> bytes:
        return b"".join(x.tobytes() for x in state)

    @staticmethod
    def from_key(k: bytes) -> List[np.ndarray]:
        arr = np.frombuffer(k, dtype=np.uint8)
        return [arr[i * 256 : (i + 1) * 256].reshape(16, 16).copy() for i in range(3)]

    def step(self, state: List[np.ndarray], x: int, y: int) -> List[np.ndarray]:
        out: List[np.ndarray] = [None, None, None]  # type: ignore
        h = x >> 3

        for rbp in range(3):
            acc = np.zeros((16, 16), dtype=np.int32)

            for rcx in range(3):
                t6 = tdpbssd(np.zeros((16, 16), dtype=np.int32), state[rcx], self.A[x])
                t4 = repack_16x16_to_tile4x64(trunc_i32_to_u8(t6))
                acc = tdpbssd(acc, self.C[h][y][rbp][rcx], t4)

            acc = tdpbssd(acc, state[rbp], self.B[x])
            out[rbp] = trunc_i32_to_u8(acc)

        return out

    @staticmethod
    def valid(state: List[np.ndarray]) -> bool:
        flat = np.concatenate([x.reshape(-1) for x in state])
        chk = flat[:0x240].astype(np.int16)
        chk = np.where(chk >= 128, chk - 256, chk)

        for i in range(36):
            blk = chk[i * 16 : (i + 1) * 16]
            if np.any(blk < 0):
                return False
            if int(blk.sum()) >= 2:
                return False

        return True

    @staticmethod
    def accept(state: List[np.ndarray]) -> bool:
        flat = np.concatenate([x.reshape(-1) for x in state])
        # Final byte check at 0x412380 -> offset 0x110 in 0x300 state blob.
        return Solver.valid(state) and int(flat[0x110]) == 1

    def solve_round(self, round_idx: int) -> Optional[List[Tuple[int, int]]]:
        start_state = [self.R[round_idx][i].copy() for i in range(3)]
        start_key = self.key(start_state)

        q = deque([start_key])
        parent: Dict[bytes, Tuple[Optional[bytes], Optional[Tuple[int, int]]]] = {
            start_key: (None, None)
        }

        found: Optional[bytes] = None

        while q:
            cur = q.popleft()
            st = self.from_key(cur)

            if parent[cur][0] is not None and self.accept(st):
                found = cur
                break

            for x, y in ALPHABET:
                ns = self.step(st, x, y)
                if not self.valid(ns):
                    continue
                nk = self.key(ns)
                if nk in parent:
                    continue
                parent[nk] = (cur, (x, y))
                q.append(nk)

        if found is None:
            return None

        path: List[Tuple[int, int]] = []
        k = found
        while True:
            pk, sym = parent[k]
            if pk is None:
                break
            path.append(sym)  # type: ignore[arg-type]
            k = pk
        path.reverse()
        return path


def encode_path(path: List[Tuple[int, int]]) -> str:
    return "".join(HEX[x] + str(y) for x, y in path)


def main() -> None:
    if not BIN_PATH.exists():
        raise SystemExit("chall binary not found in current directory")

    binary = BIN_PATH.read_bytes()
    solver = Solver(binary)

    all_inputs: List[str] = []
    for r in range(3):
        path = solver.solve_round(r)
        if path is None:
            raise SystemExit(f"No accepted path found for round {r}")
        s = encode_path(path)
        all_inputs.append(s)
        print(f"round {r}: len={len(path)}")
        print(s)

    print("\nPaste these lines to remote service in order:")
    for s in all_inputs:
        print(s)


if __name__ == "__main__":
    main()
