import requests

BANNER = r'''
   ____      _               _____ _     _     _     _ 
  / ___|   _| |__   ___ _ __| ____| |   (_)___| |__ | |
 | |  | | | | '_ \ / _ \ '__|  _| | |   | / __| '_ \| |
 | |__| |_| | |_) |  __/ |  | |___| |___| \__ \ | | |_|
  \____\__,_|_.__/ \___|_|  |_____|_____|_|___/_| |_(_)

        CYBERSHIELD IV – TERMINAL INTERFACE
---------------------------------------------------------
'''

API_URL = "http://127.0.0.1:8000/analyze"

def send_signal(signal: str):
    try:
        res = requests.get(API_URL, params={"signal": signal})
        return res.json()
    except Exception as e:
        return {"error": str(e)}

def main():
    print(BANNER)
    print("Type any threat signal to route it through the AI mesh.")
    print("Type 'exit' to quit.\n")

    while True:
        user_input = input(">> ")

        if user_input.lower() in ["exit", "quit"]:
            print("Shutting down terminal interface...")
            break

        if not user_input.strip():
            print("Please enter a valid signal.\n")
            continue

        print("\n--- ROUTING SIGNAL ---")
        response = send_signal(user_input)
        print(response)
        print("\n")

if __name__ == "__main__":
    main()
