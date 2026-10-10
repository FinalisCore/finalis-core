#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Local devnet chaos harness for two-phase finality liveness and safety.

Runs N validator processes on loopback with fast timing. Every directed link i -> j goes through
an in-process TCP proxy, so links can be cut (partitions, isolation, flaps) and delayed without
root. Nodes only dial their configured peers (addrman rejects loopback addresses), so the proxies
are the only paths between nodes.

The run alternates fault windows (crashes, restarts, partitions, isolation flaps, latency) with
healed windows. Each healed window must show progress (a new height finalized) within
--recovery-deadline, otherwise it is recorded as a stall.

Safety: every "finalized height=H transition=T" log line from every node is compared; two
transitions at one height is a fork and stops the run (exit 3).

--byzantine K makes the first K validators Byzantine (needs a build configured with
-DFINALIS_CHAOS_BYZANTINE=ON): they prevote and precommit every proposal they see, ignoring every
rule, and send two different proposals to different peers when they lead. Honest validators must
stay safe and live with K <= f. Byzantine nodes are never crashed; crashes take at most
max(1, f - K) honest nodes.

--tx-interval S sends a payment every S seconds (after the first reward settlement funds the
validators) through a random running node's lightserver and tracks it to finality.

Liveness: stalls (exit 2), recovery times, rounds per height, catch-up lag at the end.

Usage:
  scripts/chaos_devnet.py --nodes 7 --duration 900 --seed 1
  scripts/chaos_devnet.py --nodes 7 --byzantine 2 --build-dir build-chaos --tx-interval 1
Output: <workdir>/report.json, <workdir>/report.md, <workdir>/node<i>.log
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
import re
import signal
import socket
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PASSPHRASE = "localdevnet"  # generate_fresh_genesis.sh --profile local
FINALIZED_RE = re.compile(
    r"\] finalized height=(\d+) transition=([0-9a-f]{64}) round=(\d+) commit_round=(\d+) source=(\w+)")


def log(msg: str) -> None:
    print(f"[chaos {time.strftime('%H:%M:%S')}] {msg}", flush=True)


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# --- network: one proxy per directed link -------------------------------------------------------

@dataclass
class LinkState:
    down: bool = False
    delay_ms: int = 0


class Network:
    """Directed proxies i -> j; faults are set per unordered pair."""

    def __init__(self, n: int):
        self.n = n
        self.state = {frozenset((i, j)): LinkState() for i in range(n) for j in range(n) if i < j}
        self.proxy_port: dict[tuple[int, int], int] = {}
        self.node_port: dict[int, int] = {}
        self.conns: dict[frozenset, set[asyncio.StreamWriter]] = {k: set() for k in self.state}
        self.servers: list[asyncio.base_events.Server] = []

    def link(self, i: int, j: int) -> LinkState:
        return self.state[frozenset((i, j))]

    async def start(self) -> None:
        for i in range(self.n):
            self.node_port[i] = free_port()
        for i in range(self.n):
            for j in range(self.n):
                if i == j:
                    continue
                # Listens on node j's address 127.0.0.<10+j>: node i sees each outbound peer under its
                # own IP too.
                server = await asyncio.start_server(
                    lambda r, w, i=i, j=j: self._accept(i, j, r, w), self.ip(j), 0)
                self.servers.append(server)
                self.proxy_port[(i, j)] = server.sockets[0].getsockname()[1]

    @staticmethod
    def ip(i: int) -> str:
        return f"127.0.0.{10 + i}"

    def peers_for(self, i: int) -> str:
        return ",".join(f"{self.ip(j)}:{self.proxy_port[(i, j)]}" for j in range(self.n) if j != i)

    async def _accept(self, i: int, j: int, reader, writer) -> None:
        key = frozenset((i, j))
        if self.state[key].down:
            writer.close()
            return
        try:
            # Source address 127.0.0.<10+i>: node j sees each peer under its own IP, as on a real
            # network, so an IP ban hits only that peer.
            up_reader, up_writer = await asyncio.open_connection(
                "127.0.0.1", self.node_port[j], local_addr=(self.ip(i), 0))
        except OSError:
            writer.close()
            return
        self.conns[key].update((writer, up_writer))
        try:
            await asyncio.gather(self._pump(key, reader, up_writer), self._pump(key, up_reader, writer))
        finally:
            for w in (writer, up_writer):
                self.conns[key].discard(w)
                w.close()

    async def _pump(self, key, reader, writer) -> None:
        try:
            while True:
                data = await reader.read(65536)
                if not data or self.state[key].down:
                    break
                if self.state[key].delay_ms:
                    await asyncio.sleep(self.state[key].delay_ms / 1000)
                writer.write(data)
                await writer.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            writer.close()

    def cut(self, i: int, j: int) -> None:
        key = frozenset((i, j))
        self.state[key].down = True
        for w in list(self.conns[key]):
            w.close()

    def heal(self) -> None:
        for st in self.state.values():
            st.down = False
            st.delay_ms = 0


# --- nodes ---------------------------------------------------------------------------------------

class Nodes:
    def __init__(self, args, genesis_dir: Path, net: Network, workdir: Path):
        self.args = args
        self.genesis_dir = genesis_dir
        self.net = net
        self.workdir = workdir
        self.procs: dict[int, subprocess.Popen | None] = {i: None for i in range(net.n)}
        self.rpc_port = {i: free_port() for i in range(net.n)}
        self.hard_kills: list[tuple[int, float]] = []  # (node, time)

    def cmd(self, i: int) -> list[str]:
        a = self.args
        peers = self.net.peers_for(i)
        return [
            str(a.build_dir / "finalis-node"), "--db", str(self.workdir / f"db{i}"),
            "--genesis", str(self.genesis_dir / "genesis.bin"), "--allow-unsafe-genesis-override",
            "--node-id", str(i + 1),
            "--validator-key-file", str(self.genesis_dir / "keys" / f"validator-{i + 1}.json"),
            "--validator-passphrase-env", "FINALIS_VALIDATOR_PASSPHRASE",
            "--listen", "--bind", "127.0.0.1", "--port", str(self.net.node_port[i]),
            "--no-dns-seeds", "--peers", peers, "--seeds", peers,
            "--min-block-interval-ms", str(a.block_ms),
            "--round-timeout-ms", str(a.round_timeout_ms),
            "--max-round-timeout-ms", str(a.max_round_timeout_ms),
            "--with-lightserver", "--lightserver-bind", "127.0.0.1", "--lightserver-port", str(self.rpc_port[i]),
        ]

    def rpc_url(self, i: int) -> str:
        return f"http://127.0.0.1:{self.rpc_port[i]}/rpc"

    def start(self, i: int) -> None:
        env = dict(os.environ, FINALIS_VALIDATOR_PASSPHRASE=PASSPHRASE)
        if i < self.args.byzantine:
            env["FINALIS_CHAOS_BYZANTINE"] = "1"
        logf = open(self.workdir / f"node{i}.log", "ab")
        # Own process group: the lightserver child dies with the node, also on SIGKILL.
        self.procs[i] = subprocess.Popen(self.cmd(i), stdout=logf, stderr=subprocess.STDOUT, env=env,
                                         start_new_session=True)
        logf.close()

    def stop(self, i: int, hard: bool) -> None:
        p = self.procs[i]
        if p is None:
            return
        if hard:
            self.hard_kills.append((i, time.monotonic()))
        if p.poll() is None:
            os.killpg(p.pid, signal.SIGKILL if hard else signal.SIGTERM)
            try:
                p.wait(timeout=20)
            except subprocess.TimeoutExpired:
                os.killpg(p.pid, signal.SIGKILL)
                p.wait()
        try:
            os.killpg(p.pid, signal.SIGKILL)  # lightserver child, if it outlived the node
        except ProcessLookupError:
            pass
        self.procs[i] = None

    def running(self) -> list[int]:
        return [i for i, p in self.procs.items() if p is not None and p.poll() is None]

    def exited_unexpectedly(self) -> list[tuple[int, int]]:
        return [(i, p.returncode) for i, p in self.procs.items() if p is not None and p.poll() is not None]


# --- monitor -------------------------------------------------------------------------------------

@dataclass
class Monitor:
    n: int
    workdir: Path
    offsets: dict[int, int] = field(default_factory=dict)
    by_height: dict[int, dict[str, set[int]]] = field(default_factory=dict)  # height -> transition -> nodes
    node_height: dict[int, int] = field(default_factory=dict)
    first_seen: dict[int, float] = field(default_factory=dict)
    commit_round: dict[int, int] = field(default_factory=dict)
    sources: dict[str, int] = field(default_factory=dict)
    forks: list[dict] = field(default_factory=list)

    def poll(self) -> None:
        for i in range(self.n):
            path = self.workdir / f"node{i}.log"
            if not path.exists():
                continue
            with open(path, "rb") as f:
                f.seek(self.offsets.get(i, 0))
                chunk = f.read()
            end = chunk.rfind(b"\n")
            if end < 0:
                continue
            self.offsets[i] = self.offsets.get(i, 0) + end + 1
            for line in chunk[:end].decode(errors="replace").splitlines():
                m = FINALIZED_RE.search(line)
                if m:
                    self._record(i, int(m[1]), m[2], int(m[4]), m[5])

    def _record(self, node: int, h: int, tid: str, commit_round: int, source: str) -> None:
        per = self.by_height.setdefault(h, {})
        per.setdefault(tid, set()).add(node)
        if len(per) > 1 and not any(f["height"] == h for f in self.forks):
            self.forks.append({"height": h, "transitions": {t: sorted(ns) for t, ns in per.items()}})
        self.node_height[node] = max(self.node_height.get(node, 0), h)
        self.first_seen.setdefault(h, time.monotonic())
        self.commit_round[h] = max(self.commit_round.get(h, 0), commit_round)
        self.sources[source] = self.sources.get(source, 0) + 1

    def max_height(self) -> int:
        return max(self.node_height.values(), default=0)


# --- faults --------------------------------------------------------------------------------------

class Chaos:
    def __init__(self, args, net: Network, nodes: Nodes, mon: Monitor, rng: random.Random):
        self.args, self.net, self.nodes, self.mon, self.rng = args, net, nodes, mon, rng
        self.n = net.n
        self.f = (self.n - 1) // 3
        self.windows: list[dict] = []
        self.stalls: list[dict] = []

    async def crash_restart(self, hard: bool) -> str:
        honest = list(range(self.args.byzantine, self.n))
        count = self.rng.randint(1, max(1, self.f - self.args.byzantine)) if hard else 1
        victims = self.rng.sample(honest, count)
        for v in victims:
            self.nodes.stop(v, hard)
        await asyncio.sleep(self.rng.uniform(2, self.args.max_fault_s))
        for v in victims:
            self.nodes.start(v)
        return f"{'crash' if hard else 'restart'} nodes={victims}"

    async def partition(self) -> str:
        order = list(range(self.n))
        self.rng.shuffle(order)
        k = self.rng.randint(1, self.n - 1)
        a, b = order[:k], order[k:]
        for i in a:
            for j in b:
                self.net.cut(i, j)
        await asyncio.sleep(self.rng.uniform(3, self.args.max_fault_s))
        return f"partition {sorted(a)}|{sorted(b)}"

    async def flap(self) -> str:
        v = self.rng.randrange(self.n)
        for _ in range(self.rng.randint(1, 3)):
            for j in range(self.n):
                if j != v:
                    self.net.cut(v, j)
            await asyncio.sleep(self.rng.uniform(0.5, 4))
            self.net.heal()
            await asyncio.sleep(self.rng.uniform(0.5, 3))
        return f"flap node={v}"

    async def latency(self) -> str:
        links = [k for k in self.net.state if self.rng.random() < 0.5]
        hi = self.rng.choice([200, 800, 2000])
        for k in links:
            self.net.state[k].delay_ms = self.rng.randint(20, hi)
        await asyncio.sleep(self.rng.uniform(5, self.args.max_fault_s))
        return f"latency links={len(links)} max_ms={hi}"

    async def crash_and_partition(self) -> str:
        v = self.rng.randrange(self.args.byzantine, self.n)
        self.nodes.stop(v, True)
        desc = await self.partition()
        self.nodes.start(v)
        return f"crash node={v} + {desc}"

    async def run(self, deadline: float) -> None:
        faults = [
            (lambda: self.crash_restart(True), 3),
            (lambda: self.crash_restart(False), 2),
            (self.partition, 3),
            (self.flap, 3),
            (self.latency, 2),
            (self.crash_and_partition, 1),
        ]
        weights = [w for _, w in faults]
        while time.monotonic() < deadline and not self.mon.forks:
            fn = self.rng.choices([f for f, _ in faults], weights)[0]
            h0 = self.mon.max_height()
            t0 = time.monotonic()
            desc = await fn()
            self.net.heal()
            healed_at = time.monotonic()
            h_heal = self.mon.max_height()
            log(f"fault done: {desc} (height {h0} -> {h_heal} during fault)")
            # Healed window: the network must finalize a new height within the deadline.
            recovered_at = None
            while time.monotonic() < healed_at + self.args.recovery_deadline:
                await asyncio.sleep(0.5)
                if self.mon.max_height() > h_heal:
                    recovered_at = time.monotonic()
                    break
                if self.mon.forks:
                    break
            window = {
                "fault": desc, "fault_s": round(healed_at - t0, 1), "height_before": h0,
                "progress_during_fault": h_heal - h0,
                "recovery_s": None if recovered_at is None else round(recovered_at - healed_at, 1),
            }
            self.windows.append(window)
            if recovered_at is None and not self.mon.forks:
                window["stall"] = True
                self.stalls.append(window)
                log(f"STALL: no new height {self.args.recovery_deadline}s after healing '{desc}' "
                    f"(height {h_heal}, running={self.nodes.running()})")
                if self.args.stop_on_stall:
                    return
            calm = self.rng.uniform(self.args.calm_s / 2, self.args.calm_s)
            await asyncio.sleep(max(0.0, calm - (time.monotonic() - healed_at)))


# --- transaction traffic -------------------------------------------------------------------------

class Traffic:
    """Payments between validators through random running nodes' lightservers, tracked to finality."""

    def __init__(self, args, genesis_dir: Path, nodes: Nodes, workdir: Path, rng: random.Random):
        self.args, self.genesis_dir, self.nodes, self.rng = args, genesis_dir, nodes, rng
        manifest = dict(line.split("=", 1) for line in (genesis_dir / "manifest.env").read_text().splitlines()
                        if "=" in line and not line.startswith("#"))
        self.addresses = [manifest[f"VALIDATOR_{i + 1}_ADDRESS"] for i in range(args.nodes)]
        self.wallet_dir = workdir / "wallets"
        self.sent = 0
        self.rejected = 0
        self.pending: dict[str, float] = {}   # txid -> submit time
        self.pending_sender: dict[str, int] = {}
        self.via: dict[str, tuple[int, float]] = {}  # txid -> (accepting node, submit time)
        self.finalized: dict[str, float] = {}  # txid -> latency s
        self.lost: list[str] = []              # accepted, not finalized within --tx-lost-s
        self.busy: set[int] = set()

    async def _rpc(self, url: str, method: str, params: dict) -> dict | None:
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
        proc = await asyncio.create_subprocess_exec(
            "curl", "-s", "-m", "3", "-X", "POST", "-H", "Content-Type: application/json", "-d", body, url,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await proc.communicate()
        try:
            return json.loads(out).get("result")
        except (ValueError, AttributeError):
            return None

    async def _send(self, sender: int) -> None:
        self.busy.add(sender)
        try:
            running = self.nodes.running()
            if not running:
                self.busy.discard(sender)
                return
            via = self.rng.choice(running)
            to = self.rng.choice([i for i in range(self.args.nodes) if i != sender])
            wallet = self.wallet_dir / f"w{sender}"
            wallet.mkdir(parents=True, exist_ok=True)
            proc = await asyncio.create_subprocess_exec(
                str(self.args.build_dir / "finalis-cli"), "send", "--to", self.addresses[to],
                "--amount-units", str(self.rng.randint(1000, 50000)), "--rpc", self.nodes.rpc_url(via),
                "--file", str(self.genesis_dir / "keys" / f"validator-{sender + 1}.json"), "--pass", PASSPHRASE,
                "--db", str(wallet), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
            out, _ = await proc.communicate()
            text = out.decode(errors="replace")
            m = re.search(r"txid=([0-9a-f]{64})", text)
            if proc.returncode == 0 and m and "accepted=yes" in text:
                self.sent += 1
                self.pending[m[1]] = time.monotonic()
                self.via[m[1]] = (via, time.monotonic())
                # One payment in flight per sender: the wallet selects finalized UTXOs, so a second
                # payment before the first finalizes would double-spend its input.
                self.pending_sender[m[1]] = sender
                return
            self.rejected += 1
        except BaseException:
            self.busy.discard(sender)
            raise
        self.busy.discard(sender)

    async def run(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            await asyncio.sleep(self.args.tx_interval)
            idle = [i for i in range(self.args.nodes) if i not in self.busy]
            if idle:
                asyncio.create_task(self._send(self.rng.choice(idle)))

    async def track(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            await asyncio.sleep(2)
            await self.check_pending()

    async def check_pending(self) -> None:
        running = self.nodes.running()
        if not running:
            return
        now = time.monotonic()
        for txid, t0 in list(self.pending.items()):
            if now - t0 > self.args.tx_lost_s:
                del self.pending[txid]
                self.lost.append(txid)
                self.busy.discard(self.pending_sender.pop(txid, -1))
        for txid in list(self.pending)[:50]:
            res = await self._rpc(self.nodes.rpc_url(self.rng.choice(running)), "get_tx_status", {"txid": txid})
            if res and res.get("finalized"):
                start = self.pending.pop(txid, None)  # the tracker and the final check can race
                if start is not None:
                    self.finalized[txid] = time.monotonic() - start
                    self.busy.discard(self.pending_sender.pop(txid, -1))

    def summary(self) -> dict:
        lat = list(self.finalized.values())
        # Lost payments whose accepting node was crash-killed within 30 s: its mempool (and any log
        # lines not yet flushed) died with it. Submission is fire-and-forget; wallets must re-submit.
        crashed = sum(1 for t in self.lost if any(
            n == self.via[t][0] and 0 <= k - self.via[t][1] <= 30 for n, k in self.nodes.hard_kills))
        return {"lost_accepting_node_crashed_within_30s": crashed,"accepted": self.sent, "rejected_or_failed": self.rejected, "finalized": len(self.finalized),
                "pending": len(self.pending), "lost": len(self.lost), "lost_txids": self.lost[:10],
                "finality_latency_s": {"p50": percentile(lat, 0.5), "p95": percentile(lat, 0.95),
                                       "max": max(lat, default=None)}}


# --- main ----------------------------------------------------------------------------------------

def make_genesis(args, workdir: Path) -> Path:
    out = workdir / "genesis"
    out.mkdir(parents=True, exist_ok=True)
    subprocess.run([str(ROOT / "scripts" / "generate_fresh_genesis.sh"), "--validators", str(args.nodes),
                    "--out-root", str(out), "--cli", str(args.build_dir / "finalis-cli")],
                   check=True, stdout=subprocess.DEVNULL)
    return sorted(p.parent for p in out.glob("*/manifest.env"))[-1]


def percentile(xs: list[float], p: float) -> float | None:
    if not xs:
        return None
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(p * (len(xs) - 1))))]


def write_report(args, workdir: Path, mon: Monitor, chaos: Chaos, nodes: Nodes, final: dict,
                 traffic: Traffic | None) -> dict:
    rec = [w["recovery_s"] for w in chaos.windows if w["recovery_s"] is not None]
    rounds = list(mon.commit_round.values())
    report = {
        "nodes": args.nodes, "byzantine": args.byzantine, "seed": args.seed, "duration_s": args.duration,
        "timing_ms": {"block": args.block_ms, "round_timeout": args.round_timeout_ms,
                      "max_round_timeout": args.max_round_timeout_ms},
        "heights_finalized": mon.max_height(),
        "forks": mon.forks,
        "stalls": chaos.stalls,
        "fault_windows": len(chaos.windows),
        "recovery_s": {"p50": percentile(rec, 0.5), "p95": percentile(rec, 0.95), "max": max(rec, default=None)},
        "commit_round_histogram": {str(r): rounds.count(r) for r in sorted(set(rounds))},
        "finalization_sources": mon.sources,
        "final": final,
        "transactions": traffic.summary() if traffic else None,
        "unexpected_exits": nodes.exited_unexpectedly(),
        "windows": chaos.windows,
    }
    (workdir / "report.json").write_text(json.dumps(report, indent=2))
    lines = [
        "# Chaos devnet report", "",
        f"- nodes: {args.nodes} (f = {(args.nodes - 1) // 3}), byzantine {args.byzantine}, seed {args.seed}, "
        f"duration {args.duration}s",
        f"- timing: block {args.block_ms} ms, round timeout {args.round_timeout_ms} ms (max {args.max_round_timeout_ms} ms)",
        f"- heights finalized: {report['heights_finalized']}",
        f"- forks: {len(mon.forks)}",
        f"- stalls: {len(chaos.stalls)} of {len(chaos.windows)} fault windows",
        f"- recovery after heal: p50 {report['recovery_s']['p50']}s, p95 {report['recovery_s']['p95']}s, "
        f"max {report['recovery_s']['max']}s",
        f"- commit rounds: {report['commit_round_histogram']}",
        f"- final: {final}",
        f"- transactions: {report['transactions']}",
        "", "| fault | fault s | progress during | recovery s |", "|---|---|---|---|",
    ]
    for w in chaos.windows:
        lines.append(f"| {w['fault']} | {w['fault_s']} | {w['progress_during_fault']} | "
                     f"{w['recovery_s'] if w['recovery_s'] is not None else 'STALL'} |")
    (workdir / "report.md").write_text("\n".join(lines) + "\n")
    return report


async def amain(args) -> int:
    workdir = Path(args.workdir or f"/tmp/finalis-chaos-{int(time.time())}").resolve()
    workdir.mkdir(parents=True, exist_ok=True)
    rng = random.Random(args.seed)
    genesis_dir = Path(args.genesis_dir).resolve() if args.genesis_dir else make_genesis(args, workdir)
    log(f"workdir={workdir} genesis={genesis_dir} nodes={args.nodes} seed={args.seed}")

    net = Network(args.nodes)
    await net.start()
    nodes = Nodes(args, genesis_dir, net, workdir)
    mon = Monitor(args.nodes, workdir)
    chaos = Chaos(args, net, nodes, mon, rng)

    async def monitor_loop():
        while True:
            mon.poll()
            await asyncio.sleep(0.5)

    mon_task = asyncio.create_task(monitor_loop())
    for i in range(args.nodes):
        nodes.start(i)
    final: dict = {}
    traffic = Traffic(args, genesis_dir, nodes, workdir, rng) if args.tx_interval > 0 else None
    stop_traffic = asyncio.Event()
    traffic_tasks = []
    if traffic:
        traffic_tasks = [asyncio.create_task(traffic.run(stop_traffic)), asyncio.create_task(traffic.track(stop_traffic))]
    try:
        warm_deadline = time.monotonic() + args.recovery_deadline * 2
        while mon.max_height() < args.warmup_heights and time.monotonic() < warm_deadline:
            await asyncio.sleep(1)
        if mon.max_height() < args.warmup_heights:
            log(f"network did not reach warmup height {args.warmup_heights}")
            final = {"error": "warmup-failed", "height": mon.max_height()}
            return 4
        log(f"warmup done at height {mon.max_height()}; chaos for {args.duration}s")
        await chaos.run(time.monotonic() + args.duration)

        # Final convergence: all faults healed, every node must reach the same tip.
        net.heal()
        for i in range(args.nodes):
            if nodes.procs[i] is None or nodes.procs[i].poll() is not None:
                nodes.start(i)
        end = time.monotonic() + args.recovery_deadline * 2
        target = mon.max_height() + 1
        while time.monotonic() < end:
            await asyncio.sleep(1)
            if all(mon.node_height.get(i, 0) >= target for i in range(args.nodes)):
                break
        final = {"target_height": target, "node_heights": {str(i): mon.node_height.get(i, 0) for i in range(args.nodes)},
                 "converged": all(mon.node_height.get(i, 0) >= target for i in range(args.nodes))}
        if traffic:
            stop_traffic.set()
            # Give in-flight payments time to finalize on the healed network.
            end = time.monotonic() + args.recovery_deadline
            while traffic.pending and time.monotonic() < end:
                await traffic.check_pending()
                await asyncio.sleep(2)
    finally:
        mon.poll()
        stop_traffic.set()
        for t in traffic_tasks:
            t.cancel()
        for i in range(args.nodes):
            nodes.stop(i, hard=False)
        mon_task.cancel()
        report = write_report(args, workdir, mon, chaos, nodes, final, traffic)
        log(f"report: {workdir / 'report.md'}")
        log(f"heights={report['heights_finalized']} forks={len(report['forks'])} stalls={len(report['stalls'])} "
            f"recovery_p95={report['recovery_s']['p95']}s final={final} tx={report['transactions']}")
    if mon.forks:
        return 3
    if chaos.stalls or not final.get("converged", False):
        return 2
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--nodes", type=int, default=7)
    ap.add_argument("--duration", type=int, default=600, help="seconds of chaos after warmup")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--workdir")
    ap.add_argument("--genesis-dir", help="reuse a generate_fresh_genesis.sh output with --nodes validators")
    ap.add_argument("--build-dir", type=Path, default=ROOT / "build")
    ap.add_argument("--block-ms", type=int, default=1000)
    ap.add_argument("--round-timeout-ms", type=int, default=2000)
    ap.add_argument("--max-round-timeout-ms", type=int, default=10000)
    ap.add_argument("--max-fault-s", type=float, default=15, help="upper bound of a fault window")
    ap.add_argument("--calm-s", type=float, default=20, help="upper bound of a healed window")
    ap.add_argument("--recovery-deadline", type=float, default=60, help="seconds after heal to finalize a new height")
    ap.add_argument("--warmup-heights", type=int, default=3)
    ap.add_argument("--stop-on-stall", action="store_true")
    ap.add_argument("--byzantine", type=int, default=0, help="first K validators are Byzantine (chaos build)")
    ap.add_argument("--tx-interval", type=float, default=0, help="seconds between payments (0: no traffic)")
    ap.add_argument("--tx-lost-s", type=float, default=120, help="an accepted payment not finalized by then is lost")
    args = ap.parse_args()
    if args.nodes < 4:
        ap.error("--nodes must be >= 4")
    if args.byzantine > (args.nodes - 1) // 3:
        ap.error("--byzantine must be <= f = (nodes - 1) // 3")
    if args.byzantine and b"CHAOS-BYZANTINE" not in (args.build_dir / "finalis-node").read_bytes():
        ap.error(f"{args.build_dir}/finalis-node is not a -DFINALIS_CHAOS_BYZANTINE=ON build")
    return asyncio.run(amain(args))


if __name__ == "__main__":
    sys.exit(main())
