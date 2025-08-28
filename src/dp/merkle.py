# src/dp/merkle.py
from __future__ import annotations
import hashlib
from typing import List, Dict

def _h(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def merkle_root(leaves: List[bytes]) -> bytes:
    if not leaves:
        return _h(b"\x00")
    level = [_h(leaf) for leaf in leaves]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            a = level[i]
            b = level[i+1] if i+1 < len(level) else a
            nxt.append(_h(a + b))
        level = nxt
    return level[0]

def merkle_path(leaves: List[bytes], index: int) -> List[Dict[str, str]]:
    if not leaves:
        return []
    layer = [_h(leaf) for leaf in leaves]
    path: List[Dict[str, str]] = []
    idx = index
    while len(layer) > 1:
        nxt = []
        for i in range(0, len(layer), 2):
            a = layer[i]
            b = layer[i+1] if i+1 < len(layer) else a
            nxt.append(_h(a + b))
            if i == idx or i+1 == idx:
                path.append({"dir": "R" if i == idx else "L", "hash": (b if i == idx else a).hex()})
                idx = len(nxt) - 1
        layer = nxt
    return path

def verify_inclusion(leaf: bytes, root_hex: str, path: List[Dict[str, str]]) -> bool:
    node = _h(leaf)
    for step in path:
        sib = bytes.fromhex(step["hash"])
        if step["dir"] == "R":
            node = _h(node + sib)
        else:
            node = _h(sib + node)
    return node.hex() == root_hex
