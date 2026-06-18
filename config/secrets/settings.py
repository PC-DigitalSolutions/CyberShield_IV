import os
from dotenv import load_dotenv

# We are telling Python EXACTLY where to look
dotenv_path = r"C:\CyberLab\CyberShield_IV\.env"

if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path)
    # This pulls the key you named CYBERSHIELD_API_KEY
    GOOGLE_API_KEY = os.getenv("CYBERSHIELD_API_KEY")
else:
    GOOGLE_API_KEY = None

if not GOOGLE_API_KEY:
    print("--- ERROR: API KEY NOT FOUND IN .ENV ---")
