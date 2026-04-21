#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

import argparse
import hashlib
from pathlib import Path


def to_cpp_array(data: bytes, cols: int = 12) -> str:
    parts = [f"0x{b:02x}" for b in data]
    lines = []
    for i in range(0, len(parts), cols):
      lines.append("  " + ", ".join(parts[i:i+cols]))
    return ",\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="Convert genesis.bin to embedded C++ source")
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--out", dest="out", required=True)
    args = ap.parse_args()

    data = Path(args.inp).read_bytes()
    h = hashlib.sha256(hashlib.sha256(data).digest()).digest()
    hash_hex = h.hex()
    hash_init = ", ".join(f"0x{b:02x}" for b in h)

    content = f'''#include "genesis/embedded_mainnet.hpp"

namespace finalis::genesis {{

// Generated from {args.inp}
// sha256d(genesis.bin) = {hash_hex}
const std::uint8_t MAINNET_GENESIS_BIN[] = {{
{to_cpp_array(data)}
}};

const std::size_t MAINNET_GENESIS_BIN_LEN = {len(data)};

const Hash32 MAINNET_GENESIS_HASH{{{{{hash_init}}}}};

}}  // namespace finalis::genesis
'''
    Path(args.out).write_text(content)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
