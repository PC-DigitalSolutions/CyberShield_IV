"""
assess_login — pure scoring function for Sentinel IAM.
No LLM, no network, no database.  All inputs come from the caller.
"""
from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any


# ---------------------------------------------------------------------------
# Haversine helpers
# ---------------------------------------------------------------------------

_R_KM = 6_371.0  # Earth mean radius in km


def _haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Return great-circle distance in kilometres."""
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlam = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlam / 2) ** 2
    return 2 * _R_KM * math.asin(math.sqrt(a))


def _parse_utc(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


# ---------------------------------------------------------------------------
# Public function
# ---------------------------------------------------------------------------

def assess_login(req: dict[str, Any], seed: dict[str, Any]) -> dict[str, Any]:
    """
    Score a login request against the user baseline.

    Parameters
    ----------
    req  : dict with keys user_id, ip, device_id, geo, timestamp
    seed : contents of data/iam/baselines.json

    Returns
    -------
    dict with risk_score, risk_level, flags, baseline, explanation

    Raises
    ------
    KeyError  when the user_id is not in seed["users"]
    """
    user_id: str = req["user_id"]
    users: dict = seed["users"]

    if user_id not in users:
        raise KeyError(user_id)

    user = users[user_id]
    scoring = seed["scoring"]
    cities: dict = seed.get("cities", {})
    threat_ips: list = seed.get("threat_ips", [])

    flags: list[str] = []
    points = 0

    # 1. impossible_travel
    last_login = user.get("last_login", {})
    last_geo = last_login.get("geo")
    last_ts_str = last_login.get("timestamp")
    req_geo: str = req["geo"]

    if last_geo and last_ts_str and last_geo != req_geo:
        c_last = cities.get(last_geo)
        c_req = cities.get(req_geo)
        if c_last and c_req:
            try:
                t_last = _parse_utc(last_ts_str)
                t_req = _parse_utc(req["timestamp"])
                hours = abs((t_req - t_last).total_seconds()) / 3600
                if hours > 0:
                    dist_km = _haversine(
                        c_last["lat"], c_last["lon"],
                        c_req["lat"],  c_req["lon"],
                    )
                    speed = dist_km / hours
                    if speed > scoring["impossible_travel_kmh"]:
                        flags.append("impossible_travel")
                        points += scoring["impossible_travel"]
            except (ValueError, KeyError):
                pass  # unknown city → no flag

    # 2. ip_on_threat_list
    if req["ip"] in threat_ips:
        flags.append("ip_on_threat_list")
        points += scoring["ip_on_threat_list"]

    # 3. new_device
    if req["device_id"] not in user.get("known_devices", []):
        flags.append("new_device")
        points += scoring["new_device"]

    # 4. off_hours
    try:
        utc_hour = _parse_utc(req["timestamp"]).hour
        h_start, h_end = user.get("usual_hours_utc", [0, 24])
        if not (h_start <= utc_hour < h_end):
            flags.append("off_hours")
            points += scoring["off_hours"]
    except (ValueError, KeyError):
        pass

    risk_score = min(points, scoring["max_score"])

    # Determine level (first entry whose min <= score)
    risk_level = "Low"
    for entry in scoring["levels"]:
        if risk_score >= entry["min"]:
            risk_level = entry["level"]
            break

    # Build explanation
    parts: list[str] = []
    if "impossible_travel" in flags and last_geo:
        parts.append(f"Login from {req_geo} after a recent {last_geo} session")
    if "ip_on_threat_list" in flags:
        parts.append("IP is on the threat list")
    if "new_device" in flags:
        parts.append("unrecognized device")
    if "off_hours" in flags:
        utc_hour = _parse_utc(req["timestamp"]).hour
        parts.append(f"outside usual hours ({utc_hour:02d}:00 UTC)")
    explanation = ("; ".join(parts) + ".") if parts else "No anomalies detected."

    baseline = {
        "usual_geo": user.get("home_geo"),
        "usual_hours_utc": user.get("usual_hours_utc"),
        "known_devices": len(user.get("known_devices", [])),
    }

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "flags": flags,
        "baseline": baseline,
        "explanation": explanation,
    }
