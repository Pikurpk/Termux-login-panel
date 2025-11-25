#!/usr/bin/env python3
import os, sys, time, hashlib, requests, socket
from urllib.parse import urlparse

GREEN = "\033[1;32m"
RED = "\033[1;31m"
CYAN = "\033[1;36m"
YELLOW = "\033[1;33m"
RESET = "\033[0m"

def clear():
    os.system("clear")

def banner():
    print(f"""
{RED}██╗     ██╗   ██╗ ██████╗██╗███████╗███████╗██████╗ 
██║     ██║   ██║██╔════╝██║██╔════╝██╔════╝██╔══██╗
██║     ██║   ██║██║     ██║█████╗  █████╗  ██████╔╝
██║     ██║   ██║██║     ██║██╔══╝  ██╔══╝  ██╔══██╗
███████╗╚██████╔╝╚██████╗██║██║     ███████╗██║  ██║
╚══════╝ ╚═════╝  ╚═════╝╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝{RESET}
        {GREEN}Lucifer Termux Tools Pack{RESET}
            Powered by Foysal
""")

# ----------------------------- #
# 1. Network Scanner (ARP)
# ----------------------------- #
def arp_scan():
    os.system("pkg install net-tools -y >/dev/null")
    print(GREEN + "\nScanning local devices...\n" + RESET)
    os.system("arp -a")

# ----------------------------- #
# 2. IP Info Lookup
# ----------------------------- #
def ip_lookup():
    ip = input("\nEnter IP or Domain: ")
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}").json()
        print("\n")
        for k, v in r.items():
            print(f"{k} : {v}")
    except:
        print(RED + "Error fetching info!" + RESET)

# ----------------------------- #
# 3. Port Scanner
# ----------------------------- #
def port_scan():
    target = input("\nTarget IP: ")
    ports = [21, 22, 23, 53, 80, 443, 8080]
    print("\nScanning common ports...\n")
    for port in ports:
        s = socket.socket()
        s.settimeout(0.5)
        try:
            s.connect((target, port))
            print(GREEN + f"[OPEN] Port {port}" + RESET)
        except:
            print(RED + f"[CLOSED] Port {port}" + RESET)

# ----------------------------- #
# 4. System Information
# ----------------------------- #
def system_info():
    print("\n")
    os.system("uname -a")
    os.system("termux-info")

# ----------------------------- #
# 5. File Search
# ----------------------------- #
def file_search():
    name = input("\nEnter filename: ")
    print("\nSearching...\n")
    os.system(f"find $HOME -iname '*{name}*' 2>/dev/null")

# ----------------------------- #
# 6. Wordlist Generator
# ----------------------------- #
def wordlist():
    word = input("\nBase word: ")
    count = int(input("How many? "))
    file = open("wordlist.txt", "w")
    for i in range(count):
        file.write(f"{word}{i}\n")
    file.close()
    print(GREEN + "\nWordlist saved as wordlist.txt" + RESET)

# ----------------------------- #
# 7. Password Strength Checker
# ----------------------------- #
def pass_strength():
    ps = input("\nEnter Password: ")
    strength = 0
    if len(ps) >= 8: strength += 1
    if any(c.isdigit() for c in ps): strength += 1
    if any(c.isalpha() for c in ps): strength += 1
    if any(c in "!@#$%^&*()_+" for c in ps): strength += 1

    levels = ["VERY WEAK", "WEAK", "MEDIUM", "STRONG"]
    print(GREEN + f"\nPassword Strength: {levels[strength]}\n" + RESET)

# ----------------------------- #
# 8. Website Status Checker
# ----------------------------- #
def web_status():
    url = input("\nEnter website URL: ")
    try:
        r = requests.get(url)
        print(GREEN + f"\nStatus: {r.status_code} (OK)\n" + RESET)
    except:
        print(RED + "\nWebsite unreachable!\n" + RESET)

# ----------------------------- #
# 9. Storage Usage
# ----------------------------- #
def storage():
    os.system("du -h ~ | tail")

# ----------------------------- #
# 10. Internet Speed Test
# ----------------------------- #
def speed_test():
    os.system("pip install speedtest-cli -q")
    os.system("speedtest-cli")

# ----------------------------- #
# 11. Hash Generator
# ----------------------------- #
def hash_generate():
    text = input("\nEnter text: ")
    print("\nMD5:", hashlib.md5(text.encode()).hexdigest())
    print("SHA256:", hashlib.sha256(text.encode()).hexdigest())

# ----------------------------- #
# 12. YouTube Info Grabber
# ----------------------------- #
def yt_info():
    os.system("pip install yt-dlp -q")
    url = input("\nEnter YouTube URL: ")
    os.system(f"yt-dlp --get-title --get-duration --get-description {url}")

# ----------------------------- #
# Main Menu
# ----------------------------- #
def menu():
    while True:
        clear()
        banner()
        print(f"""
{CYAN}==============================
      Lucifer Tools Menu
=============================={RESET}
1. Network Scanner
2. IP Info Lookup
3. Port Scanner
4. System Info
5. File Search
6. Wordlist Generator
7. Password Strength Check
8. Website Status Check
9. Storage Usage
10. Internet Speed Test
11. Hash Generator
12. YouTube Video Info
0. Exit
""")

        choice = input("Choose Option: ")

        if choice == "1": arp_scan()
        elif choice == "2": ip_lookup()
        elif choice == "3": port_scan()
        elif choice == "4": system_info()
        elif choice == "5": file_search()
        elif choice == "6": wordlist()
        elif choice == "7": pass_strength()
        elif choice == "8": web_status()
        elif choice == "9": storage()
        elif choice == "10": speed_test()
        elif choice == "11": hash_generate()
        elif choice == "12": yt_info()
        elif choice == "0":
            clear()
            print("Goodbye Lucifer!")
            sys.exit()
        else:
            print(RED + "Invalid Option!" + RESET)

        input("\nPress Enter to return menu...")

menu()
