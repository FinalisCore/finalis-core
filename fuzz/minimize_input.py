#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Shrinks a fuzz reproducer while the standalone fuzz binary still reports the same failure.

Usage: fuzz/minimize_input.py BINARY INPUT OUTPUT --expect 'oracle=precommit-durable'

The input is replayed with `BINARY FILE` (each file against a fresh node, as the smoke binaries do).
A candidate is kept when the binary exits non-zero and its stderr contains --expect. Delta debugging
over byte chunks (halving the chunk size), then single bytes; no randomness, so the result is
reproducible. Each step runs the binary --repeat times and keeps the candidate only if every run
fails the same way, so a timing-dependent shrink is not accepted.
"""
import argparse
import os
import subprocess
import sys
import tempfile


def fails(binary, data, expect, repeat, env):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        f.write(data)
        path = f.name
    try:
        for _ in range(repeat):
            r = subprocess.run([binary, path], capture_output=True, env=env, timeout=300)
            if r.returncode == 0 or expect.encode() not in r.stderr:
                return False
        return True
    finally:
        os.unlink(path)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("binary")
    p.add_argument("input")
    p.add_argument("output")
    p.add_argument("--expect", required=True)
    p.add_argument("--repeat", type=int, default=2)
    a = p.parse_args()
    env = dict(os.environ, FINALIS_TEST_QUIET_LOGS="1", FINALIS_FUZZ_ARTIFACT_DIR=tempfile.gettempdir())
    data = open(a.input, "rb").read()
    if not fails(a.binary, data, a.expect, a.repeat, env):
        sys.exit("input does not reproduce: " + a.expect)
    chunk = max(1, len(data) // 2)
    while chunk >= 1:
        i = 0
        changed = False
        while i < len(data):
            cand = data[:i] + data[i + chunk:]
            if cand and fails(a.binary, cand, a.expect, a.repeat, env):
                data = cand
                changed = True
            else:
                i += chunk
        if not changed:
            chunk //= 2
    open(a.output, "wb").write(data)
    print(f"{a.input}: {os.path.getsize(a.input)} -> {len(data)} bytes ({a.expect})")


if __name__ == "__main__":
    main()
