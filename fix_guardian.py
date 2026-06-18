import google.generativeai as genai
import os

# 1. SETUP - Replace with your actual API key from your Google Cloud tab
API_KEY = "YOUR_PASTE_KEY_HERE" 
genai.configure(api_key=API_KEY)

print("--- Starting El Guardián Connection Test ---")

try:
    # 2. NEW LOGIC - Using 'system_instruction' (The weekend update fix)
    model = genai.GenerativeModel(
        model_name="gemini-1.5-flash",
        system_instruction="You are El Guardián. Mission: FIFA World Cup 2026. Tone: Latin Passion, Cyber Strength."
    )

    # 3. TEST REQUEST
    response = model.generate_content("Status report: Is the stadium perimeter secure?")
    
    print("\nSUCCESS! El Guardián responded:")
    print("-" * 30)
    print(response.text)
    print("-" * 30)

except Exception as e:
    print("\nFAILED! Here is the error for the logs:")
    print(str(e))
    print("\nTIP: If it says 'API_KEY_INVALID', check your Google Cloud Console tab.")