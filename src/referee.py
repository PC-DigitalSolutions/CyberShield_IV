class SidelineReferee:
    def __init__(self):
        self.name = "Sideline Referee"

    def check_compliance(self, origin: str, destination: str):
        origin = origin.strip().upper()
        destination = destination.strip().upper()

        # Mexico LFPDPPP Check
        if origin == "MEXICO" and destination != "MEXICO":
            return {"status": "VIOLATION", "law": "Mexico Federal Law (LFPDPPP)", "action": "AUDIT"}
        
        # EU GDPR Check
        if origin in ["EU", "GERMANY", "FRANCE", "SPAIN"] and destination not in ["EU", "USA"]:
            return {"status": "HIGH RISK", "law": "GDPR (Article 44)", "action": "ENFORCE_ENCRYPTION"}

        return {"status": "COMPLIANT", "action": "PLAY ON"}
