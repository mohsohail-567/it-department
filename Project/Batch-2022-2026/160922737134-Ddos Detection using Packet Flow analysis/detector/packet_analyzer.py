import re
from collections import Counter, defaultdict
from datetime import datetime
from ipaddress import ip_address

from detector.risk import compute_risk_score


IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
NUM_RE = re.compile(r"\b\d+\b")
ISO_TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}")


def _safe_ip(s: str) -> str | None:
    try:
        ip_address(s)
        return s
    except Exception:
        return None


def _parse_csvish_line(line: str):
    """
    Expected:
    timestamp,src_ip,dst_ip,protocol,length,flags(optional)
    """
    parts = [p.strip() for p in line.split(",")]
    if len(parts) < 5:
        return None

    ts_raw, src, dst, proto, length = parts[0:5]
    flags = parts[5] if len(parts) >= 6 else ""

    src_ok = _safe_ip(src)
    dst_ok = _safe_ip(dst)
    if not src_ok or not dst_ok:
        return None

    # timestamp parse (best-effort)
    ts = None
    try:
        ts = datetime.fromisoformat(ts_raw.replace(" ", "T"))
    except Exception:
        ts = None

    # length parse
    try:
        length_i = int(re.sub(r"[^\d]", "", length)) if length else 0
    except Exception:
        length_i = 0

    proto = (proto or "UNK").upper()[:10]
    flags = (flags or "").upper()[:40]
    return {"ts": ts, "src": src_ok, "dst": dst_ok, "proto": proto, "length": length_i, "flags": flags}


def _parse_loose_line(line: str):
    """
    For random logs: try to extract 2 IPs (src,dst), optional protocol, optional length.
    """
    ips = IP_RE.findall(line)
    ips = [i for i in ips if _safe_ip(i)]
    if len(ips) < 2:
        return None
    src, dst = ips[0], ips[1]

    proto = "UNK"
    u = line.upper()
    for p in ("TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS"):
        if p in u:
            proto = p
            break

    # Guess length as the largest number in line (bounded)
    nums = [int(n) for n in NUM_RE.findall(line)]
    length_i = 0
    if nums:
        length_i = max(nums)
        # Bound to sane packet sizes; if it's huge, set 0 (likely a port or pid)
        if length_i > 20000:
            length_i = 0

    ts = None
    m = ISO_TS_RE.search(line)
    if m:
        try:
            ts = datetime.fromisoformat(m.group(0).replace(" ", "T"))
        except Exception:
            ts = None

    flags = ""
    if "SYN" in u:
        flags = "SYN"
    if "ACK" in u:
        flags = (flags + "|ACK").strip("|")

    return {"ts": ts, "src": src, "dst": dst, "proto": proto, "length": length_i, "flags": flags}


def analyze_packet_text(raw_text: str) -> dict:
    """
    Output is a JSON-serializable dict, safe for DB storage and hashing.
    """
    lines = [ln.strip() for ln in raw_text.splitlines() if ln.strip()]
    parsed = []

    # Parse lines
    for ln in lines[:200000]:  # safety cap
        item = _parse_csvish_line(ln)
        if not item:
            item = _parse_loose_line(ln)
        if item:
            parsed.append(item)

    total_lines = len(lines)
    total_packets = len(parsed)

    # If nothing parsed, still return a safe structure
    if total_packets == 0:
        analysis = {
            "status": "ok",
            "message": "No recognizable packet rows were parsed. Try CSV format: timestamp,src_ip,dst_ip,protocol,length,flags",
            "total_lines": total_lines,
            "total_packets": 0,
            "top_targets": [],
            "top_sources": [],
            "protocol_distribution": {},
            "findings": ["No parsable packet flow entries found."],
            "risk_score": 0.0,
            "risk_factors": [],
        }
        return analysis

    proto_counts = Counter(p["proto"] for p in parsed)
    src_counts = Counter(p["src"] for p in parsed)
    dst_counts = Counter(p["dst"] for p in parsed)

    # Unique sources per target
    sources_per_dst = defaultdict(set)
    syn_per_dst = Counter()
    for p in parsed:
        sources_per_dst[p["dst"]].add(p["src"])
        if "SYN" in (p.get("flags") or ""):
            syn_per_dst[p["dst"]] += 1

    # Timing window (best-effort)
    timestamps = [p["ts"] for p in parsed if p["ts"] is not None]
    window_seconds = None
    if len(timestamps) >= 2:
        tmin = min(timestamps)
        tmax = max(timestamps)
        window_seconds = max(1.0, (tmax - tmin).total_seconds())

    # Compute per-target packet rate if possible
    target_rates = []
    if window_seconds:
        for dst, count in dst_counts.items():
            target_rates.append((dst, count / window_seconds))

    # Top lists
    top_targets = []
    for dst, cnt in dst_counts.most_common(8):
        top_targets.append({
            "dst_ip": dst,
            "packets": cnt,
            "unique_sources": len(sources_per_dst.get(dst, set())),
            "syn_packets": int(syn_per_dst.get(dst, 0)),
            "pps_est": round((cnt / window_seconds), 2) if window_seconds else None,
        })

    top_sources = []
    for src, cnt in src_counts.most_common(8):
        top_sources.append({
            "src_ip": src,
            "packets": cnt,
        })

    # Heuristic findings
    findings = []
    risk_factors = []

    # Primary victim candidate
    victim = dst_counts.most_common(1)[0][0]
    victim_packets = dst_counts[victim]
    victim_unique_sources = len(sources_per_dst[victim])

    findings.append(f"Parsed {total_packets} packet entries from {total_lines} lines.")
    findings.append(f"Most targeted destination: {victim} ({victim_packets} packets, {victim_unique_sources} unique sources).")

    # DDoS-like signals
    if victim_unique_sources >= 20 and victim_packets >= 500:
        findings.append("High unique-source concentration toward one target suggests potential distributed attack behavior.")
        risk_factors.append("many_sources_one_target")

    if victim_unique_sources >= 50 and victim_packets >= 1500:
        findings.append("Very high unique-source burst toward a single victim is strongly suspicious (DDoS-like).")
        risk_factors.append("very_many_sources_one_target")

    # Rate-based
    if window_seconds:
        victim_pps = victim_packets / window_seconds
        findings.append(f"Estimated time window: ~{int(window_seconds)}s, victim packet rate: ~{victim_pps:.2f} packets/sec.")
        if victim_pps >= 200:
            findings.append("High packet rate toward victim detected.")
            risk_factors.append("high_pps_to_victim")
        if victim_pps >= 600:
            findings.append("Extreme packet rate toward victim detected.")
            risk_factors.append("extreme_pps_to_victim")
    else:
        findings.append("Timestamps were missing/insufficient; rate-based checks were limited.")

    # SYN flood signal (optional)
    syns = syn_per_dst.get(victim, 0)
    if syns >= 300:
        findings.append("Large number of SYN packets to the victim may indicate SYN flood behavior.")
        risk_factors.append("syn_flood_signal")


    # Single-source flood signal
    top_src, top_src_pkts = src_counts.most_common(1)[0]
    if top_src_pkts >= max(800, int(total_packets * 0.6)):
        findings.append("One source contributes a dominant share of traffic; could be a flood or misconfigured sender.")
        risk_factors.append("single_source_dominance")

    # Compute final risk score
    score = compute_risk_score(
        total_packets=total_packets,
        victim_packets=victim_packets,
        victim_unique_sources=victim_unique_sources,
        window_seconds=window_seconds,
        victim_syn_packets=int(syns),
        top_src_packets=int(top_src_pkts),
        risk_factors=risk_factors,
    )

    analysis = {
        "status": "ok",
        "message": "Analysis completed.",
        "total_lines": total_lines,
        "total_packets": total_packets,
        "time_window_seconds_est": int(window_seconds) if window_seconds else None,
        "victim_candidate": {
            "dst_ip": victim,
            "packets": victim_packets,
            "unique_sources": victim_unique_sources,
            "syn_packets": int(syns),
        },
        "top_targets": top_targets,
        "top_sources": top_sources,
        "protocol_distribution": dict(proto_counts),
        "findings": findings,
        "risk_factors": risk_factors,
        "risk_score": round(float(score), 2),
    }
    return analysis