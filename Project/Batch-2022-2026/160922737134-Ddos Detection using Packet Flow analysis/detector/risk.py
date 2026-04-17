def compute_risk_score(
    *,
    total_packets: int,
    victim_packets: int,
    victim_unique_sources: int,
    window_seconds: float | None,
    victim_syn_packets: int,
    top_src_packets: int,
    risk_factors: list[str],
) -> float:
    """
    Returns a 0..100 score.
    Simple but explainable heuristic scoring for student demos + enterprise-looking UX.
    """
    score = 0.0

    # Baseline volume
    if total_packets >= 200:
        score += 10
    if total_packets >= 800:
        score += 10
    if total_packets >= 2000:
        score += 10

    # Target concentration (victim focus)
    if victim_packets >= 400:
        score += 10
    if victim_packets >= 1200:
        score += 10

    # Distributed nature
    if victim_unique_sources >= 10:
        score += 10
    if victim_unique_sources >= 25:
        score += 10
    if victim_unique_sources >= 60:
        score += 10

    # Rate-based (if timestamps exist)
    if window_seconds:
        pps = victim_packets / max(1.0, window_seconds)
        if pps >= 150:
            score += 15
        if pps >= 400:
            score += 10

    # SYN flood indicator
    if victim_syn_packets >= 150:
        score += 10
    if victim_syn_packets >= 500:
        score += 10

    # Single-source dominance (not DDoS, but severe)
    if top_src_packets >= max(600, int(total_packets * 0.6)):
        score += 10

    # Factor bonuses
    bonus_map = {
        "many_sources_one_target": 8,
        "very_many_sources_one_target": 12,
        "high_pps_to_victim": 8,
        "extreme_pps_to_victim": 12,
        "syn_flood_signal": 10,
        "single_source_dominance": 6,
    }
    for f in risk_factors:
        score += bonus_map.get(f, 0)

    return max(0.0, min(100.0, score))


def risk_level_from_score(score: float) -> str:
    if score >= 85:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 35:
        return "Medium"
    return "Low"