import os

def show_hub():
    os.system('cls' if os.name == 'nt' else 'clear')
    cyan = "\033[96m"
    white = "\033[97m"
    green = "\033[92m"
    reset = "\033[0m"
    
    print(f"{cyan}{'='*60}")
    print(f"{white}         CYBERSHIELD AI (EL GUARDIÁN) - COMMAND HUB")
    print(f"{cyan}{'='*60}{reset}")
    
    agents = [
        ("ANTI-SCAMMER GOALIE", "VIGILANT"),
        ("SIDELINE REFEREE", "COMPLIANT"),
        ("RED CARD SENTINEL", "AUTHENTICATING"),
        ("LAS BARRAS BRAVAS TRIAGE", "MONITORING")
    ]
    
    for name, status in agents:
        print(f"{white}{name:<25} | {green}STATUS: {status}{reset}")
    
    print(f"{cyan}{'-'*60}")
    print(f"{white}Strength. Vigilance. Intelligence.")
    print(f"CyberShield AI (El Guardián).")
    print(f"{cyan}{'='*60}{reset}")

if __name__ == '__main__':
    show_hub()
