# Patrick Turner
# CSC 842 - Tool #3 - Updated
# Dr. Welu
# July 16, 2026


#       Sniff53 v2 is a pcap file reader that scans captured packets for DNS tunneling.



# sniff53v2.py — Sniff53
# DNS tunneling detection on port 53.


# New in this version is detailed reporting on errors in logfiles and --log option to save results to file.

# Usage:
#	python sniff53v2.py capture.pcap --log logfile.txt
#	python sniff53v2.py queries.log --log logfile.txt
#	python sniff53v2.py capture.pcap --min-score 0.5 --log logfile.txt
#	python sniff53v2.py capture.pcap --features --log features.txt
#	python sniff53v2.py capture.pcap --summary --log summary.txt

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


# ─────────────────────────────────────────────────────────────────────────────
# Data class for DNS Event.  Defines the DNS event from packet data.

@dataclass
class DNSEvent:
	timestamp: datetime
	src_ip: str
	query_name: str
	query_type: str       # A, AAAA, TXT, MX, etc.
	response_code: str    # NOERROR, NXDOMAIN, SERVFAIL, etc.
	payload_size: int
	features: dict = field(default_factory=dict)   # Updated by enrich function.
	is_response: bool = False  # True if = DNS response packet,

	@property
	def subdomain(self) -> str:
		parts = self.query_name.rstrip(".").split(".")
		return ".".join(parts[:-2]) if len(parts) > 2 else ""
#		Parses all characters to the left of the domain name. This is the focus on
#		where attackers code malicious data.



# ----------------------------------------------------------------------
#Program takes either a plain text log file or pcap file. Both result
# in DNS event objects.

def load(source: str | Path) -> Iterator[DNSEvent]:
		# Picks the correct loader.
	path = Path(source)
	if not path.exists():
		raise FileNotFoundError(f"Not found: {path}")
	if path.suffix.lower() in (".pcap", ".cap"):
		yield from _read_pcap(path)
	else:
		yield from _read_logfile(path)

#----------------------------------------------------------------------
# Reads the logfile to parse fields.

# Shared warning lists populated by _read_logfile, consumed by analyse().
_warn_ts:   list[tuple[int, str, str]] = []
_warn_skip: list[tuple[int, str, str]] = []


def _read_logfile(path: Path) -> Iterator[DNSEvent]:
	"""
	Reads a space-delimited log file and yields DNSEvent objects.
	Warnings are stored in _warn_ts and _warn_skip so analyse() can
	write them to both stderr and the log file after iteration ends.
	"""
	global _warn_ts, _warn_skip
	_warn_ts   = []
	_warn_skip = []

	with open(path) as f:
		for lineno, raw in enumerate(f, 1):
			line = raw.strip()
			if not line or line.startswith("#"):
				continue
			parts = line.split()
			if len(parts) < 4:
				_warn_skip.append((lineno, line, f"too few fields ({len(parts)} found, 4 required)"))
				continue
			try:
				ts = datetime.fromisoformat(parts[0])
			except ValueError:
				fallback = datetime.now()
				_warn_ts.append((lineno, parts[0], fallback.strftime("%H:%M:%S")))
				ts = fallback
			ip_parts = parts[1].split(".")
			if len(ip_parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in ip_parts):
				_warn_skip.append((lineno, line, f"invalid source IP: {parts[1]!r}"))
				continue
			if "." not in parts[2]:
				_warn_skip.append((lineno, line, f"query name does not look like a domain: {parts[2]!r}"))
				continue
			yield DNSEvent(
				timestamp=ts,
				src_ip=parts[1],
				query_name=parts[2],
				query_type=parts[3].upper(),
				response_code=parts[4].upper() if len(parts) > 4 else "NOERROR",
				payload_size=0,
			)


def _report_logfile_warnings(log_file=None):
	"""
	Prints warnings from log file parsing to stderr, and mirrors them
	to the log file if one is open. Called by analyse() after the
	event loop completes.
	"""
	import re

	def out(text):
		print(text, file=sys.stderr)
		if log_file:
			log_file.write(re.sub(r"\033\[[0-9;]*m", "", text) + "\n")

	if _warn_ts:
		out(_c(f"\n  [!] {len(_warn_ts)} line(s) had unparseable timestamps - used current time as fallback:", YEL))
		for lineno, bad_val, fallback in _warn_ts:
			out(_c(f"      line {lineno}: {bad_val!r} -> used {fallback}", DIM))

	if _warn_skip:
		out(_c(f"\n  [!] {len(_warn_skip)} line(s) skipped due to formatting errors:", YEL))
		for lineno, raw_line, reason in _warn_skip:
			preview = raw_line[:60] + ("..." if len(raw_line) > 60 else "")
			out(_c(f"      line {lineno}: {reason}", DIM))
			out(_c(f"              {preview!r}", DIM))
#-------------------------------------------------------------------------
# Reads pcap file to parse fields. Picks up packets in or out for port 53.

def _read_pcap(path: Path) -> Iterator[DNSEvent]:
	DNS_PORT = 53
	with open(path, "rb") as f:
		# Global header: tells us byte order and the link layer type.
		global_header = f.read(24)
		if len(global_header) < 24:
			raise ValueError("File too short to be a valid pcap")
		magic = global_header[:4]
		if magic not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
			raise ValueError("Not a valid pcap file")
		endian = "<" if magic == b"\xd4\xc3\xb2\xa1" else ">"

		# linktype tells us what kind of frame each packet starts with.
		linktype = struct.unpack(endian + "I", global_header[20:24])[0]
		if linktype not in (1, 101, 228):
			raise ValueError(f"Unsupported linktype {linktype} (need Ethernet=1, raw IP=101, or raw IPv4=228)")
		eth_offset = 14 if linktype == 1 else 0

		while True:
			pkt_hdr = f.read(16)            # per-packet header: timestamp + lengths
			if len(pkt_hdr) < 16:
				break                   # end of file
			ts_sec, ts_usec, incl_len, _ = struct.unpack(endian + "IIII", pkt_hdr)
			raw = f.read(incl_len)
			if len(raw) < incl_len:
				break

			ts = datetime.fromtimestamp(ts_sec + ts_usec / 1_000_000)
			ip = raw[eth_offset:]
			# Only handle IPv4 (version nibble == 4) carrying UDP (protocol 17).
			if len(ip) < 20 or (ip[0] >> 4) != 4 or ip[9] != 17:
				continue

			ihl = (ip[0] & 0xF) * 4         # IP header length in bytes (variable!)
			src_ip = socket.inet_ntoa(ip[12:16])
			dst_ip = socket.inet_ntoa(ip[16:20])
			udp = ip[ihl:]
			if len(udp) < 8:
				continue
			sport, dport = struct.unpack("!HH", udp[0:4])
			if DNS_PORT not in (sport, dport):
				continue                     # not DNS traffic, skip

			# udp[8:] is the DNS message itself (8-byte UDP header stripped)
			event = _parse_dns_payload(udp[8:], ts, src_ip, dst_ip, len(raw))
			if event:
				yield event

#----------------------------------------------------------------------------
# Parse DNS payload for queries and responses.
def _parse_dns_payload(data: bytes, ts: datetime, src_ip: str, dst_ip: str, pkt_size: int) -> DNSEvent | None:
	if len(data) < 12:
		return None	# smaller than a DNS header, can't be valid

	flags = struct.unpack("!H", data[2:4])[0]
	is_response = bool((flags >> 15) & 1)
	if struct.unpack("!H", data[4:6])[0] == 0:
		return None

				# Walk the DNS "question" labels ("www" "google" "com")
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
			# Translate integer codes to readable strings.
	qtype_map = {1:"A",2:"NS",5:"CNAME",6:"SOA",12:"PTR",
				 15:"MX",16:"TXT",28:"AAAA",33:"SRV",255:"ANY"}
	qtype = qtype_map.get(struct.unpack("!H", data[offset:offset+2])[0], "?")
	rcode_map = {0:"NOERROR",1:"FORMERR",2:"SERVFAIL",3:"NXDOMAIN",5:"REFUSED"}
	rcode = rcode_map.get(flags & 0xF, "UNKNOWN")

	if is_response:
		# Attribute the rcode back to the host that asked (dst_ip), not
		# the resolver that answered (src_ip). query_name is kept for
		# reference but the scoring logic ignores it for response events.
		return DNSEvent(
			timestamp=ts, src_ip=dst_ip,
			query_name=".".join(labels),
			query_type=qtype, response_code=rcode,
			payload_size=pkt_size,
			is_response=True,
		)

	return DNSEvent(
		timestamp=ts, src_ip=src_ip,
		query_name=".".join(labels),
		query_type=qtype, response_code=rcode,
		payload_size=pkt_size,
	)

#------------------------------------------------------------------------
# Entrophy function - measures how random the patterns.


def _entropy(s: str) -> float:
	if not s:
		return 0.0
	n = len(s)
	return -sum((c/n) * math.log2(c/n) for c in Counter(s.lower()).values())

#------------------------------------------------------------------------
# Class hosttracker
#	Tracks, per host, within the configured time window:
#	  - every query timestamp   -> query rate
#	  - every response code     -> NXDOMAIN ratio
#	  - every subdomain entropy -> average entropy (used by host_score)

class HostTracker:

	def __init__(self, window_seconds: int = 60):
		self._window = timedelta(seconds=window_seconds)
		self._ts:      dict[str, deque] = defaultdict(deque)   # ip -> timestamps
		self._rc:      dict[str, deque] = defaultdict(deque)   # ip -> response codes
		self._entropy: dict[str, list]  = defaultdict(list)    # ip -> entropy values seen

	def update(self, event: DNSEvent) -> dict:
		ip, now = event.src_ip, event.timestamp
		self._ts[ip].append(now)
		self._rc[ip].append(event.response_code)

		# Slide the window forward: drop entries older than `now - window`
		cutoff = now - self._window
		while self._ts[ip] and self._ts[ip][0] < cutoff:
			self._ts[ip].popleft()
			self._rc[ip].popleft()

		# Entropy history is kept separately and isn't pruned by time —
		# it's small (one float per query) and host_score() only needs
		# an average, so simplicity wins here over strict windowing.
		sub = event.subdomain
		if sub:
			self._entropy[ip].append(_entropy(sub))

		count = len(self._ts[ip])
		nx    = sum(1 for r in self._rc[ip] if r == "NXDOMAIN")
		return {
			"query_rate":     round(count / self._window.total_seconds(), 4),
			"nxdomain_ratio": round(nx / count, 3) if count else 0.0,
			"host_score":     self.host_score(ip),
		}

#-----------------------------------------------------------------------------
# Score the host in question.

	def host_score(self, ip: str) -> float:
		ts = self._ts.get(ip)
		rc = self._rc.get(ip)
		if not ts or len(ts) < 3:
			return 0.0

		count   = len(ts)
		rate    = count / self._window.total_seconds()
		nx      = sum(1 for r in rc if r == "NXDOMAIN") / count
		ent_avg = sum(self._entropy.get(ip, [0])) / max(len(self._entropy.get(ip, [1])), 1)

		s  = (1.0 if rate >= 0.5 else 0.8 if rate >= 0.2 else 0.6 if rate >= 0.08 else 0.3 if rate >= 0.03 else 0.0) * 0.40
		s += (1.0 if ent_avg >= 4.0 else 0.7 if ent_avg >= 3.5 else 0.4 if ent_avg >= 3.0 else 0.0) * 0.35
		s += (0.9 if nx >= 0.7 else 0.5 if nx >= 0.4 else 0.0) * 0.25
		return min(round(s, 3), 1.0)

#-----------------------------------------------------------------------
# Connects ingest and scoring to store data in event.features for thw score function.

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
	event.features.update(tracker.update(event))  # adds query_rate, nxdomain_ratio, host_score
	return event


# -----------------------------------------------------------------------
# Combines every feature into a final suspicion score from 0.0 to 1.0.

def score(event: DNSEvent) -> float:
	f = event.features
	e = f.get("entropy", 0)
	rules = [
		# entropy: the strongest single signal — high-entropy subdomains
		# are the hallmark of base64/hex-encoded tunnel payloads
		(1.0 if e >= 4.5 else 0.8 if e >= 4.0 else 0.5 if e >= 3.5 else 0.2 if e >= 3.0 else 0.0,  0.25),

		# subdomain length: tunneling tools cram as much data as possible
		# into each query, producing unusually long subdomains
		(1.0 if f.get("subdomain_len",0) >= 60 else 0.7 if f.get("subdomain_len",0) >= 40 else 0.3 if f.get("subdomain_len",0) >= 25 else 0.0,  0.15),

		# query type: TXT records carry arbitrary text and are a favourite
		# for exfil tools; other rare types (MX/NULL/ANY/NAPTR) are a
		# weaker but still useful signal
		(0.6 if f.get("is_txt") else 0.4 if f.get("is_rare_type") else 0.0,  0.10),

		# query rate: how fast is this host sending DNS queries right now —
		# automated tooling tends to be much faster than human browsing
		(1.0 if f.get("query_rate",0) >= 1.0 else 0.7 if f.get("query_rate",0) >= 0.3 else 0.4 if f.get("query_rate",0) >= 0.08 else 0.0,  0.15),

		# NXDOMAIN ratio: malware using algorithmically generated domains
		# burns through many non-existent domains before finding a live one
		(0.8 if f.get("nxdomain_ratio",0) >= 0.7 else 0.4 if f.get("nxdomain_ratio",0) >= 0.4 else 0.0,  0.10),

		# digit ratio: hex-encoded payloads are dense with numeric characters,
		# which normal domain names rarely are
		(1.0 if f.get("digit_ratio",0) >= 0.6 else 0.6 if f.get("digit_ratio",0) >= 0.35 else 0.0,  0.10),

		# host-level aggregate (see HostTracker.host_score): the only
		# signal here that looks at a host's behaviour over time rather
		# than a single query — this is what catches beaconing and DGA
		# patterns that no individual query would flag on its own
		(f.get("host_score", 0.0),  0.40),
	]
	return min(round(sum(v * w for v, w in rules), 3), 1.0)
#----------------------------------------------------------------------
# Triggers returns a reason why a host was flagged.

def triggers(event: DNSEvent) -> list[str]:
	f = event.features
	e = f.get("entropy", 0)
	hits = []
	if e >= 3.0:
		hits.append("entropy")
	if f.get("subdomain_len", 0) >= 25:
		hits.append("long_subdomain")
	if f.get("is_txt"):
		hits.append("txt_type")
	elif f.get("is_rare_type"):
		hits.append("rare_type")
	if f.get("query_rate", 0) >= 0.08:
		hits.append("query_rate")
	if f.get("nxdomain_ratio", 0) >= 0.4:
		hits.append("nxdomain")
	if f.get("digit_ratio", 0) >= 0.35:
		hits.append("digit_ratio")
	if f.get("host_score", 0) >= 0.3:
		hits.append("host_pattern")  # beaconing / sustained anomalous behaviour
	return hits
#----------------------------------------------------------------------
# Output to screen

R="\033[0m"; BOLD="\033[1m"; RED="\033[31m"; YEL="\033[33m"; CYN="\033[36m"; DIM="\033[2m"

def _c(text, *codes):
	"""Wrap text in ANSI colour/style codes, then reset afterwards."""
	return "".join(codes) + text + R

def _severity(sc):
	"""Maps a numeric score to a human-readable label and colour."""
	if sc >= 0.75: return "HIGH  ", RED
	if sc >= 0.45: return "MEDIUM", YEL
	return "LOW   ", CYN

def _print_event(event, sc, show_features, indent="  "):
	"""
	Prints one line for a flagged query. No longer repeats the source IP —
	that's now shown once in the host's group header instead — so each
	row only needs to show time, score, severity, type, and the query.
	"""
	label, col = _severity(sc)
	f = event.features
	print(
		f"{indent}{event.timestamp.strftime('%H:%M:%S')}  "
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
		print(_c(f"{indent}  " + "  ".join(parts), DIM))


def _print_host_header(ip: str, count: int, peak: float, checks: list[str]):
	"""
	Prints a banner introducing a group of flagged queries from one host,
	including which detection signals fired (the "reason") so the reader
	doesn't have to infer it from the raw query list below.
	"""
	_, col = _severity(peak)
	print(_c(f"\n  \u25b8 {ip}", BOLD, col) + _c(f"   {count} flagged quer{'ies' if count != 1 else 'y'}, peak {peak:.3f}", DIM))
	if checks:
		print(_c(f"    reason: {', '.join(checks)}", DIM))
	print("  " + "─" * 60)

#------------------------------------------------------------------------
# Analyse and Main
# Reads events, enriches and scores each one,
# prints flagged queries as they're found, then prints a final summary
# grouped by source host.

def analyse(source, min_score=0.40, window=60, show_features=False, summary_only=False, log_path=None):
	tracker       = HostTracker(window)
	host_hits     = defaultdict(list)   # ip -> list of scores that crossed the threshold
	host_events   = defaultdict(list)   # ip -> list of (event, score) pairs, in time order
	host_triggers = defaultdict(set)    # ip -> union of every signal name that fired
	total         = flagged = 0

	# Open the log file if requested. All plain-text output is written here
	# in addition to the coloured output on screen. The log file strips ANSI
	# codes so it stays readable in any text editor.
	log_file = open(log_path, "w") if log_path else None

	def tee(text=""):
		"""Print to screen and, if a log file is open, also write there."""
		print(text)
		if log_file:
			# strip ANSI escape sequences before writing to the file
			import re
			clean = re.sub(r"\033\[[0-9;]*m", "", text)
			log_file.write(clean + "\n")

	run_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

	if not summary_only:
		tee(f"\nSniff53")
		tee(f"source: {source}  |  threshold: {min_score}  |  window: {window}s")
		if log_file:
			log_file.write(f"run: {run_ts}\n")
	elif log_file:
		log_file.write(f"Sniff53\n")
		log_file.write(f"source: {source}  |  threshold: {min_score}  |  window: {window}s\n")
		log_file.write(f"run: {run_ts}\n")

	try:
		for event in load(source):
			# Every event (query or response) updates the host tracker so
			# rate/NXDOMAIN/entropy history stays accurate, even though
			# response events themselves are never scored or printed.
			enrich(event, tracker)
			if event.is_response:
				continue
			total += 1
			sc = score(event)
			if sc >= min_score:
				flagged += 1
				host_hits[event.src_ip].append(sc)
				host_events[event.src_ip].append((event, sc))
				host_triggers[event.src_ip].update(triggers(event))
	except (FileNotFoundError, ValueError) as e:
		print(f"Error: {e}", file=sys.stderr)
		if log_file: log_file.close()
		sys.exit(1)

	# Report any log file parsing warnings to stderr and the log file
	_report_logfile_warnings(log_file)

	# Per-host detail, worst host first, queries in time order within each
	if not summary_only and host_hits:
		ranked_ips = sorted(host_hits.items(), key=lambda kv: -max(kv[1]))
		for ip, scores in ranked_ips:
			peak = max(scores)
			checks = sorted(host_triggers[ip])
			_, col = _severity(peak)
			# screen output (coloured)
			print(_c(f"\n  \u25b8 {ip}", BOLD, col) + _c(f"   {len(scores)} flagged quer{'ies' if len(scores) != 1 else 'y'}, peak {peak:.3f}", DIM))
			if checks:
				print(_c(f"    reason: {', '.join(checks)}", DIM))
			print("  " + "─" * 60)
			# log file output (plain text)
			if log_file:
				log_file.write(f"\n  [{_severity(peak)[0].strip()}] {ip}   {len(scores)} flagged quer{'ies' if len(scores) != 1 else 'y'}, peak {peak:.3f}\n")
				if checks:
					log_file.write(f"    reason: {', '.join(checks)}\n")
				log_file.write("  " + "-" * 60 + "\n")
			for event, sc in host_events[ip]:
				label, col = _severity(sc)
				line = (
					f"  {event.timestamp.strftime('%H:%M:%S')}  "
					f"{sc:.3f}  "
					f"{label.strip():<6}  "
					f"{event.query_type:<5}  "
					f"{event.query_name}"
				)
				# screen (coloured)
				print(
					f"  {event.timestamp.strftime('%H:%M:%S')}  "
					f"{_c(f'{sc:.3f}', BOLD)}  "
					f"{_c(label, col)}  "
					f"{event.query_type:<5}  "
					f"{event.query_name}"
				)
				# log (plain)
				if log_file:
					log_file.write(line + "\n")
				if show_features:
					f2 = event.features
					parts = [f"entropy={f2.get('entropy',0):.2f}", f"sub_len={f2.get('subdomain_len',0)}",
							 f"qrate={f2.get('query_rate',0):.2f}/s", f"nxdom={f2.get('nxdomain_ratio',0):.2f}"]
					if f2.get("is_txt"):       parts.append("TXT=yes")
					if f2.get("is_rare_type"): parts.append("rare_type=yes")
					feat_line = "      " + "  ".join(parts)
					print(_c(feat_line, DIM))
					if log_file: log_file.write(feat_line + "\n")

	# final summary: a compact scoreboard, one line per host
	pct = flagged / total * 100 if total else 0
	tee(f"\n── Summary " + "─" * 38)
	tee(f"  Queries analysed : {total}")
	tee(f"  Flagged          : {flagged}  ({pct:.1f}%)")

	if host_hits:
		print(_c(f"\n  {'HOST':<16} {'HITS':>5}  {'PEAK':>5}  REASON", BOLD))
		if log_file:
			log_file.write(f"\n  {'HOST':<16} {'HITS':>5}  {'PEAK':>5}  REASON\n")
		for ip, scores in sorted(host_hits.items(), key=lambda kv: -max(kv[1]))[:10]:
			peak = max(scores)
			label, col = _severity(peak)
			reason = ", ".join(sorted(host_triggers[ip])) or "-"
			print(f"  {_c(ip, col):<{16+len(col)+len(R)}} {len(scores):>5}  {peak:>5.2f}  {_c(reason, DIM)}")
			if log_file:
				log_file.write(f"  {ip:<16} {len(scores):>5}  {peak:>5.2f}  {reason}\n")

	if not flagged:
		tee("\n  No suspicious activity at this threshold.")
	tee()

	if log_file:
		log_file.close()
		print(_c(f"  results written to: {log_path}", DIM))


if __name__ == "__main__":
	p = argparse.ArgumentParser(description="DNS tunneling detection on port 53.")
	p.add_argument("source")                                                 		# the .pcap or .log file to analyse
	p.add_argument("--min-score", "-s", type=float, default=0.40, metavar="FLOAT")    	# alert threshold (0.0-1.0)
	p.add_argument("--window",    "-w", type=int,   default=60,   metavar="SECONDS")  	# sliding window for rate/NXDOMAIN features
	p.add_argument("--features",  "-f", action="store_true")                  		# print raw feature values under each flagged query
	p.add_argument("--summary",         action="store_true")                  		# suppress per-query lines, show only the summary
	p.add_argument("--log", "-l", default=None, metavar="FILE",
		help="write results to a plain-text log file in addition to screen output")
	args = p.parse_args()
	analyse(args.source, args.min_score, args.window, args.features, args.summary, args.log)
