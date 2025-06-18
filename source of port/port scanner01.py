"""This is a Python-based cybersecurity tool designed 
to detect open network ports and analyze suspicious URLs for phishing threats.
It’s powered by rule-based AI logic, without needing to train any machine learning 
models. It is lightweight, fast, and works entirely from the command line.


💡 Key Features:

🔍 Port Scanner

Scans the first 1024 TCP ports on a target IP address

Identifies which ports are open and collects basic banner information

Assigns a risk level to each open port (High, Medium, Low)

🕵️ Phishing Detection

Analyzes URLs using intelligent heuristics:

Keyword detection (login, verify, bank, etc.)

Suspicious characters (like @ or -)

Length and structure of the URL

Gives a warning if the URL shows phishing behavior

🌍 Geo IP & WHOIS Lookup

Retrieves geolocation data like:

City, country, ISP, and coordinates using ipinfo.io

Performs a WHOIS search on the domain to get:

Registrar, creation/expiry dates, and domain ownership details

📦 Full Report Generator

Automatically saves all results to a well-organized .json file

Includes port list, banners, phishing score, geo info, and WHOIS data

Helps security analysts and students understand attack surfaces

🖥️ Technologies Used:

Python 3

socket for network scanning

re for regex-based phishing rules

requests for API calls

colorama for colored CLI output

python-whois for domain lookup

json for report saving



"""



import socket   # for port scanning.
import re   #regular expressions to find the phishing urls.
import sys  #script to interact with the system its running on ( In this program in terminal )
import json #using to create and save a report file
import requests #sending data to or retrieving data from a web server
from datetime import datetime
from colorama import init, Fore, Style  #it used to add color and styling to text in the terminal/command line.
# Initialize colorama for cross-platform color support

init(autoreset=True)# it makes the colour reset after each print.

def banner():
    print("""_
    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀ ___.                                .__   _____   
__ ___.__.\_ |__   ___________  __  _  ______ |  |_/ ____\  
_/ ___<   |  | | __ \_/ __ \_  __ \ \ \/ \/ /  _ \|  |\   __\   
\  \___\___  | | \_\ \  ___/|  | \/  \     (  <_> )  |_|  |     
 \___  > ____| |___  /\___  >__|      \/\_/ \____/|____/__|     
    
     \/\/          \/     \/                                    
""")
    print(Fore.CYAN + Style.BRIGHT + "\n" + "="*60)#for = in the terminal
    print(Fore.MAGENTA + " AI-Powered Port Scanner & Phishing Detection Tool")#text for the terminal
    print(Fore.CYAN + "="*60 + "\n")#for = in the terminal in end 
# Port scanning starts....
def scan_ports(ip):
    open_ports = [] # it is using collect and store all the open ports found during port scanning.-- using list
    banner_grabs = {}
    print(Fore.YELLOW + f"[+] Scanning IP: {ip} (Ports 1-1024)\n")#colour for the text and using the "f" formetting .
    for port in range(1, 1025):#check all the ports 1 to 1024 to find the open port
        try:#the bunch of code that is used to find the open ports.
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)#Create a new TCP socket using IPv4 addresses and store it in a variable named sock.
            sock.settimeout(0.2)#it waits for 200 milli sec for a single port.
            sock.connect((ip, port))#it is used to connect the socket in the given ip and port.
            open_ports.append(port)#if the port is open then it will be added to the list of open_ports.
            try:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")#it sends the empty http request to the server.
                banner = sock.recv(1024).decode(errors="ignore").strip()#it grabs the banner information from thr server.
                banner_grabs[port] = banner#store the banner info.
            except:
                banner_grabs[port] = "No banner received"
            sock.close()
        except:
            continue
    return open_ports, banner_grabs

def port_risk_level(port):#it show the rick level of the port.
    high_risk = {21, 23, 25, 80, 110, 139, 143, 445, 3389}
    if port in high_risk:
        return "High 🔴"
    elif port < 1024:
        return "Medium 🟡"
    else:
        return "Low 🟢"#scan is done ..!!!
    
    #the phishing detection starts here.
    
def check_phishing(url):# basiclaly using the phishing terms to detetuct the phishing
    suspicious_reasons = []
    if "-" in url or "@" in url or "!" in url or "$" in url or "&" in url  or len(url) > 75:
        suspicious_reasons.append("Unusual characters or length")
    if re.search(r"(free|login|verify|update|bank|secure|password100%|wow|gov.refund.link|KYC Update|Bank Alert|)", url, re.IGNORECASE):
        suspicious_reasons.append("Contains phishing keywords")
    is_phishing = bool(suspicious_reasons)
    return is_phishing, suspicious_reasons
#it shows the geo location information of the ip address.
def get_geo_info(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        if response.status_code == 200:
            data = response.json()
            return {
                "IP": ip,
                "City": data.get("city"),
                "Region": data.get("region"),
                "Country": data.get("country"),
                "ISP": data.get("org"),
                "Location": data.get("loc")
            }
        else:
            return {"error": "Failed to fetch IP info"}
    except Exception as e:
        return {"error": str(e)}

def save_report(ip, ports, banners, url, phishing, reasons, geo_info):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"scan_report_{ip}_{timestamp}.json"
    report = {
        "timestamp": timestamp,
        "target_ip": ip,
        "open_ports": ports,
        "banners": banners,
        "geo_info": geo_info,
        "phishing_check": {
            "url": url,
            "is_phishing": phishing,
            "reasons": reasons
        }
    }
    with open(filename, "w") as f:
        json.dump(report, f, indent=2)
    print(Fore.CYAN + f"\n[✓] Report saved as {filename}")

def main_menu():
    banner()
    print(Fore.BLUE + "1. Port Scan an IP")
    print("2. Phishing URL Detection")
    print("3. Full Scan & Generate Report")
    print("4. Exit")

    choice = input(Fore.WHITE + "\nEnter your choice (1/2/3/4): ")

    if choice == '1':
        ip = input("Enter target IP address (e.g., 192.168.1.1): ")
        open_ports, banners = scan_ports(ip)
        if open_ports:
            print(Fore.GREEN + "\n[✓] Open Ports:")
            for port in open_ports:
                print(Fore.LIGHTGREEN_EX + f" - Port {port} | Risk: {port_risk_level(port)}")
                print(Fore.YELLOW + f"   Banner: {banners[port]}")
        else:
            print(Fore.RED + "[!] No open ports found.")
    elif choice == '2':
        url = input("Enter URL to check (e.g., https://secure-login.com): ")
        phishing, reasons = check_phishing(url)
        if phishing:
            print(Fore.RED + "[!] Suspicious URL detected!")
            for reason in reasons:
                print(Fore.LIGHTRED_EX + f" - {reason}")
        else:
            print(Fore.GREEN + "[✓] URL appears safe.")
    elif choice == '3':
        ip = input("Enter IP to scan: ")
        url = input("Enter URL to check: ")
        open_ports, banners = scan_ports(ip)
        phishing, reasons = check_phishing(url)
        geo_info = get_geo_info(ip)
        print(Fore.BLUE + "\n[+] IP Geolocation Info:")
        for k, v in geo_info.items():
            print(f"{k}: {v}")
        save_report(ip, open_ports, banners, url, phishing, reasons, geo_info)
    elif choice == '4':
        print(Fore.MAGENTA + "\n[!] Exiting... Stay secure!")
        sys.exit()
    else:
        print(Fore.RED + "\n[!] Invalid input. Try again.")

if __name__ == "__main__": #like refreshing the page.
    while True:
        main_menu()
        input(Fore.CYAN + "\nPress Enter to return to menu...")
