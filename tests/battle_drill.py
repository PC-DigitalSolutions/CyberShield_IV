import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.core.router import ElGuardianCNS
from src.utils.utr import generate_unified_report
from src.goalie import AntiScammerGoalie
from src.referee import SidelineReferee
from src.sentinel import RedCardSentinel
from src.triage import LasBarrasBravasTriage

def run_test():
    print("--- CYBERSHIELD IV TACTICAL TEST ---")
    
    # 1. Initialize Components
    cns = ElGuardianCNS()
    goalie = AntiScammerGoalie()
    referee = SidelineReferee()
    sentinel = RedCardSentinel()
    triage = LasBarrasBravasTriage()

    # 2. Define a High-Threat Scenario
    # Scenario: A deepfake video (Sentinel) coupled with a phishing link (Goalie) 
    # and a traffic spike (Triage).
    query = "URGENT: Click here to verify your identity. Is this video deepfake?"
    metadata = {
        "origin": "MEXICO", "dest": "RUSSIA", # Referee Violation
        "ai_gen": True,                       # Sentinel Red Card
        "alert": 10, "spike": 5000            # Triage Tactical Alert
    }

    print(f"\n[QUERY]: {query}")
    
    # 3. Test Routing
    assigned_agent = cns.route_to_agent(query)
    print(f"[CNS ROUTING]: Primary Agent -> {assigned_agent.upper()}")

    # 4. Simulate Agent Processing
    g_res = goalie.scan_intent(query)
    r_res = referee.check_compliance(metadata['origin'], metadata['dest'])
    s_res = sentinel.authenticate(metadata['ai_gen'])
    t_res = triage.triage_incident(metadata['alert'], metadata['spike'])

    # 5. Generate UTR
    report = generate_unified_report(g_res, r_res, s_res, t_res)

    print(f"\n[REPORT GENERATED]: ID {report['incident_id']}")
    print(f"[SEVERITY]: {report['severity']}")
    print(f"[RECOMMENDED ACTIONS]: {', '.join(report['recommended_actions'])}")
    
    if report['severity'] == "CRITICAL":
        print("\nTEST STATUS: SUCCESS - SYSTEM DETECTED MULTI-VECTOR ATTACK")
    else:
        print("\nTEST STATUS: FAILED - SYSTEM UNDER-REPORTED THREAT")

if __name__ == '__main__':
    run_test()
