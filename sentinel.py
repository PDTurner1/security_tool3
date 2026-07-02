"""
sentinel.py — DNS Sentinel
Detect DNS tunneling in a pcap or log file.

Usage:
    python sentinel.py capture.pcap
    python sentinel.py queries.log
    python sentinel.py capture.pcap --min-score 0.5
    python sentinel.py capture.pcap --features
    python sentinel.py capture.pcap --summary
"""

from __future__ import annotations

import argparse
import math
import socket
import struct
import sys
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterator


# ── Data model ─────────────────────────────────────────────────────────────────

@dataclass
class DNSEvent:
    timestamp: datetime
    src_ip: str
    query_name: str
    query_type: str       # A, AAAA, TXT, MX, …
    response_code: str    # NOERROR, NXDOMAIN, SERVFAIL, …
    payload_size: int
    features: dict = field(default_factory=dict)

    @property
    def subdomain(self) -> str:
        parts = self.query_name.rstrip(".").split(".")
        return ".".join(parts[:-2]) if len(parts) > 2 else ""


# ── Ingest ─────────────────────────────────────────────────────────────────────

def load(source: str | Path) -> Iterator[DNSEvent]:
    path = Path(source)
    if not path.exists():
        raise FileNotFoundError(f"Not found: {path}")
    if path.suffix.lower() in (".pcap", ".cap"):
        yield from _read_pcap(path)
    else:
        yield from _read_logfile(path)


def _read_logfile(path: Path) -> Iterator[DNSEvent]:
    """Space-delimited log: timestamp  src_ip  query  type  [rcode]"""
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 4:
                continue
            try:
                ts = datetime.fromisoformat(parts[0])
            except ValueError:
                ts = datetime.now()
            yield DNSEvent(
                timestamp=ts,
                src_ip=parts[1],
                query_name=parts[2],
                query_type=parts[3].upper(),
                response_code=parts[4].upper() if len(parts) > 4 else "NOERROR",
                payload_size=0,
            )


def _read_pcap(path: Path) -> Iterator[DNSEvent]:
    """Pure-stdlib pcap reader — no scapy or dpkt needed."""
    DNS_PORT = 53
    with open(path, "rb") as f:
        magic = f.read(4)
        if magic not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
            raise ValueError("Not a valid pcap file")
        endian = "<" if magic == b"\xd4\xc3\xb2\xa1" else ">"
        header = f.read(20)
        linktype = struct.unpack(endian + "HHiIH", header[:18] + b"\x00\x00")[4]
        if linktype not in (1, 101):
            raise ValueError(f"Unsupported linktype {linktype} (need Ethernet=1 or raw IP=101)")
        eth_offset = 14 if linktype == 1 else 0

        while True:
            pkt_hdr = f.read(16)
            if len(pkt_hdr) < 16:
                break
            ts_sec, ts_usec, incl_len, _ = struct.unpack(endian + "IIII", pkt_hdr)
            raw = f.read(incl_len)
            if len(raw) < incl_len:
                break

            ts  = datetime.fromtimestamp(ts_sec + ts_usec / 1_000_000)
            ip  = raw[eth_offset:]
            if len(ip) < 20 or (ip[0] >> 4) != 4 or ip[9] != 17:
                continue  # skip non-IPv4, non-UDP

            ihl = (ip[0] & 0xF) * 4
            src_ip = socket.inet_ntoa(ip[12:16])
            udp = ip[ihl:]
            if len(udp) < 8 or struct.unpack("!H", udp[2:4])[0] != DNS_PORT:
                continue

            event = _parse_dns_payload(udp[8:], ts, src_ip, len(raw))
            if event:
                yield event


def _parse_dns_payload(data: bytes, ts: datetime, src_ip: str, pkt_size: int) -> DNSEvent | None:
    if len(data) < 12:
        return None
    flags   = struct.unpack("!H", data[2:4])[0]
    if (flags >> 15) & 1:          # skip responses
        return None
    if struct.unpack("!H", data[4:6])[0] == 0:  # no questions
        return None

    offset, labels = 12, []
    try:
        while offset < len(data):
            n = data[offset]
            if n == 0:
                offset += 1; break
            if n & 0xC0 == 0xC0:
                offset += 2; break
            labels.append(data[offset+1:offset+1+n].decode("ascii", errors="replace"))
            offset += 1 + n
    except Exception:
        return None

    if not labels or offset + 4 > len(data):
        return None

    qtype_map = {1:"A",2:"NS",5:"CNAME",6:"SOA",12:"PTR",
                 15:"MX",16:"TXT",28:"AAAA",33:"SRV",255:"ANY"}
    qtype = qtype_map.get(struct.unpack("!H", data[offset:offset+2])[0], "?")
    rcode_map = {0:"NOERROR",1:"FORMERR",2:"SERVFAIL",3:"NXDOMAIN",5:"REFUSED"}
    rcode = rcode_map.get(flags & 0xF, "UNKNOWN")

    return DNSEvent(
        timestamp=ts, src_ip=src_ip,
        query_name=".".join(labels),
        query_type=qtype, response_code=rcode,
        payload_size=pkt_size,
    )


# ── Features ───────────────────────────────────────────────────────────────────

def _entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c/n) * math.log2(c/n) for c in Counter(s.lower()).values())


class HostTracker:
    """Sliding-window query rate and NXDOMAIN ratio per source IP."""
    def __init__(self, window_seconds: int = 60):
        self._window = timedelta(seconds=window_seconds)
        self._ts:    dict[str, deque] = defaultdict(deque)
        self._rc:    dict[str, deque] = defaultdict(deque)

    def update(self, event: DNSEvent) -> dict:
        ip, now = event.src_ip, event.timestamp
        self._ts[ip].append(now);  self._rc[ip].append(event.response_code)
        cutoff = now - self._window
        while self._ts[ip] and self._ts[ip][0] < cutoff:
            self._ts[ip].popleft(); self._rc[ip].popleft()
        count = len(self._ts[ip])
        nx    = sum(1 for r in self._rc[ip] if r == "NXDOMAIN")
        return {
            "query_rate":     round(count / self._window.total_seconds(), 4),
            "nxdomain_ratio": round(nx / count, 3) if count else 0.0,
        }


def enrich(event: DNSEvent, tracker: HostTracker) -> DNSEvent:
    sub   = event.subdomain
    parts = event.query_name.rstrip(".").split(".")
    event.features.update({
        "entropy":       round(_entropy(sub), 3),
        "subdomain_len": len(sub),
        "longest_label": max((len(p) for p in parts), default=0),
        "digit_ratio":   round(sum(c.isdigit() for c in sub) / len(sub), 3) if sub else 0.0,
        "is_txt":        int(event.query_type == "TXT"),
        "is_rare_type":  int(event.query_type in {"MX","NULL","ANY","NAPTR"}),
    })
    event.features.update(tracker.update(event))
    return event


# ── Scoring ────────────────────────────────────────────────────────────────────

def score(event: DNSEvent) -> float:
    f = event.features
    e = f.get("entropy", 0)
    rules = [
        # (signal_value, weight)
        (1.0 if e >= 4.5 else 0.8 if e >= 4.0 else 0.5 if e >= 3.5 else 0.2 if e >= 3.0 else 0.0,  0.40),
        (1.0 if f.get("subdomain_len",0) >= 60 else 0.7 if f.get("subdomain_len",0) >= 40 else 0.3 if f.get("subdomain_len",0) >= 25 else 0.0,  0.20),
        (0.6 if f.get("is_txt") else 0.4 if f.get("is_rare_type") else 0.0,  0.15),
        (1.0 if f.get("query_rate",0) >= 5 else 0.6 if f.get("query_rate",0) >= 2 else 0.2 if f.get("query_rate",0) >= 0.5 else 0.0,  0.20),
        (0.8 if f.get("nxdomain_ratio",0) >= 0.7 else 0.4 if f.get("nxdomain_ratio",0) >= 0.4 else 0.0,  0.15),
        (0.7 if f.get("digit_ratio",0) >= 0.6 else 0.3 if f.get("digit_ratio",0) >= 0.4 else 0.0,  0.10),
    ]
    return min(round(sum(v * w for v, w in rules), 3), 1.0)


# ── Output ─────────────────────────────────────────────────────────────────────

R="\033[0m"; BOLD="\033[1m"; RED="\033[31m"; YEL="\033[33m"; CYN="\033[36m"; DIM="\033[2m"
def _c(text, *codes): return "".join(codes) + text + R

def _severity(sc):
    if sc >= 0.75: return "HIGH  ", RED
    if sc >= 0.45: return "MEDIUM", YEL
    return "LOW   ", CYN

def _print_event(event, sc, show_features):
    label, col = _severity(sc)
    f = event.features
    print(
        f"{event.timestamp.strftime('%H:%M:%S')}  "
        f"{event.src_ip:<15}  "
        f"{_c(f'{sc:.3f}', BOLD)}  "
        f"{_c(label, col)}  "
        f"{event.query_type:<5}  "
        f"{event.query_name}"
    )
    if show_features:
        parts = [f"entropy={f.get('entropy',0):.2f}", f"sub_len={f.get('subdomain_len',0)}",
                 f"qrate={f.get('query_rate',0):.2f}/s", f"nxdom={f.get('nxdomain_ratio',0):.2f}"]
        if f.get("is_txt"):       parts.append("TXT=yes")
        if f.get("is_rare_type"): parts.append("rare_type=yes")
        print(_c("  " + "  ".join(parts), DIM))


# ── Main ───────────────────────────────────────────────────────────────────────

def analyse(source, min_score=0.40, window=60, show_features=False, summary_only=False):
    tracker   = HostTracker(window)
    host_hits = defaultdict(list)
    total     = flagged = 0
    SEP       = "─" * 78

    if not summary_only:
        print(_c("\nDNS Sentinel", BOLD, CYN))
        print(_c(f"source: {source}  |  threshold: {min_score}  |  window: {window}s\n", DIM))
        print(SEP)
        print(_c(f"{'TIME':<10}  {'SRC IP':<15}  {'SCORE'}    {'SEV':<6}  {'TYPE':<5}  QUERY", DIM))
        print(SEP)

    try:
        for event in load(source):
            total += 1
            enrich(event, tracker)
            sc = score(event)
            if sc >= min_score:
                flagged += 1
                host_hits[event.src_ip].append(sc)
                if not summary_only:
                    _print_event(event, sc, show_features)
    except (FileNotFoundError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr); sys.exit(1)

    if not summary_only:
        print(SEP)

    pct = flagged / total * 100 if total else 0
    print(_c("\n── Summary " + "─" * 38, BOLD))
    print(f"  Queries analysed : {total}")
    print(f"  Flagged          : {flagged}  ({pct:.1f}%)")

    if host_hits:
        print(_c("\n  Top offending hosts:", BOLD))
        for ip, scores in sorted(host_hits.items(), key=lambda kv: -max(kv[1]))[:10]:
            peak = max(scores)
            col  = RED if peak >= 0.75 else YEL
            bar  = _c("█" * min(int(peak * 20), 20), col)
            print(f"    {ip:<16}  hits={len(scores):<4}  avg={sum(scores)/len(scores):.2f}  peak={peak:.2f}  {bar}")

    if not flagged:
        print(_c("\n  No suspicious activity at this threshold.", DIM))
    print()


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Detect DNS tunneling in a pcap or log file.")
    p.add_argument("source")
    p.add_argument("--min-score", "-s", type=float, default=0.40, metavar="FLOAT")
    p.add_argument("--window",    "-w", type=int,   default=60,   metavar="SECONDS")
    p.add_argument("--features",  "-f", action="store_true")
    p.add_argument("--summary",         action="store_true")
    args = p.parse_args()
    analyse(args.source, args.min_score, args.window, args.features, args.summary)
