"""
tests/test_assess_login.py
Task 02: assess_login unit + route tests.
Scenarios loaded from tests/scenarios.json (copied from sentinel-iam repo).
"""
import json
import pathlib
import pytest
from fastapi.testclient import TestClient

# Load app without starting the background lifespan (no 'with' block).
from src.api.main import app

client = TestClient(app, raise_server_exceptions=True)

SCENARIOS_PATH = pathlib.Path(__file__).parent / "scenarios.json"
scenarios = {s["id"]: s for s in json.loads(SCENARIOS_PATH.read_text())["scenarios"]}


def post(req: dict) -> tuple[int, dict]:
    r = client.post("/iam/assess-login", json=req)
    try:
        body = r.json()
    except Exception:
        body = {}
    return r.status_code, body


# ---------------------------------------------------------------------------
# Scenario A: impossible travel, threat IP, new device, off-hours -> 100 Critical
# ---------------------------------------------------------------------------
def test_scenario_a():
    sc = scenarios["A"]
    status, body = post(sc["request"])
    exp = sc["expect"]
    assert status == 200
    assert body["flags"] == exp["flags"], body
    assert body["risk_score"] == exp["risk_score"], body
    assert body["risk_level"] == exp["risk_level"], body


# ---------------------------------------------------------------------------
# Scenario B: normal login -> 0 Low, no flags
# ---------------------------------------------------------------------------
def test_scenario_b():
    sc = scenarios["B"]
    status, body = post(sc["request"])
    exp = sc["expect"]
    assert status == 200
    assert body["flags"] == exp["flags"], body
    assert body["risk_score"] == exp["risk_score"], body
    assert body["risk_level"] == exp["risk_level"], body


# ---------------------------------------------------------------------------
# Scenario C: new device only -> 25 Medium
# ---------------------------------------------------------------------------
def test_scenario_c():
    sc = scenarios["C"]
    status, body = post(sc["request"])
    exp = sc["expect"]
    assert status == 200
    assert body["flags"] == exp["flags"], body
    assert body["risk_score"] == exp["risk_score"], body
    assert body["risk_level"] == exp["risk_level"], body


# ---------------------------------------------------------------------------
# Scenario D: off-hours only -> 10 Low
# ---------------------------------------------------------------------------
def test_scenario_d():
    sc = scenarios["D"]
    status, body = post(sc["request"])
    exp = sc["expect"]
    assert status == 200
    assert body["flags"] == exp["flags"], body
    assert body["risk_score"] == exp["risk_score"], body
    assert body["risk_level"] == exp["risk_level"], body


# ---------------------------------------------------------------------------
# Scenario F: threat IP + new device -> 55 High
# ---------------------------------------------------------------------------
def test_scenario_f():
    sc = scenarios["F"]
    status, body = post(sc["request"])
    exp = sc["expect"]
    assert status == 200
    assert body["flags"] == exp["flags"], body
    assert body["risk_score"] == exp["risk_score"], body
    assert body["risk_level"] == exp["risk_level"], body


# ---------------------------------------------------------------------------
# Scenario G: unknown user -> 404
# ---------------------------------------------------------------------------
def test_scenario_g():
    sc = scenarios["G"]
    status, body = post(sc["request"])
    assert status == 404
    assert body.get("detail") == "Unknown user"
