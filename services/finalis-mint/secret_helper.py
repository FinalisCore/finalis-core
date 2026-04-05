#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


def load_from_dir(secret_dir: Path, ref: str) -> str:
    if "/" in ref or "\\" in ref or ".." in ref:
        return ""
    path = secret_dir / ref
    if not path.exists() or not path.is_file():
        return ""
    return path.read_text(encoding="utf-8").strip()


def main() -> int:
    parser = argparse.ArgumentParser(description="Resolve finalis-mint secret refs from OS-managed locations.")
    parser.add_argument("--dir", default="", help="Directory containing one file per secret ref.")
    parser.add_argument("--env-prefix", default="FINALIS_MINT_SECRET_", help="Environment prefix used for secret refs.")
    parser.add_argument("ref", help="Secret ref to resolve.")
    args = parser.parse_args()

    ref = str(args.ref)
    if args.dir:
        value = load_from_dir(Path(args.dir), ref)
        if value:
            print(value)
            return 0
    if args.env_prefix:
        env_key = f"{args.env_prefix}{ref}".upper()
        value = os.environ.get(env_key, "")
        if value:
            print(value)
            return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
