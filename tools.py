# namp -sV & -sS and others 
import whois
import subprocess
import requests 
from scapy.all import IP , sniff, TCP
import json
from pathlib import Path # --> Harvester OSINT 
import re 
import datetime
import dotenv 
from tkinter import messagebox

# dotenv.load_dotenv() #
# dotenv.load_ipython_extension() # loud enviromnment varibles from .env file if exist 

def run_command(command):
    _res = subprocess.run(command, capture_output=True, text=True)
    return _res.stdout + _res.stderr

def ip_info(ip:str):
    return run_command(["sudo","nmap","-sV",ip])


def dev_info(ip:str):
    return run_command(['sudo','nmap','-sS',ip])


def get_info_sherlock(name:str):
    return run_command(["sherlock",name])

def domain_whois(domain):
    return run_command(['whois',domain])

def dos_attack(url):
    results = []
    for i in range(1000):
        try:
            res = requests.get(url)
            results.append(f"Request {i+1}: Status {res.status_code}")
        except Exception as e:
            results.append(f"Request {i+1}: Failed ({e})")
    return "\n".join(results)


def nestat():
    return run_command(['netstat', '-an'])

def get_dns_info(domain):
    return run_command(["dig", "+noall", "+answer", domain, "ANY"])

def check_header(url):
    return run_command(["curl", "-I", "-s", "-L", url])

def tracerout(target):
    return run_command(['traceroute', '-m', '15', target])

def check_ssl(domain):
    return run_command([
        "openssl",
        "s_client",
        "-connect", f"{domain}:443",
        "-servername", domain
    ])


def mail_access(email):
    return run_command(['mailaccess','investigate',email])

def send_ping(ip:str):
    return run_command(['ping',ip])

def monitorack(interface=None, count=20): # ACK monitoring by input iface like eth0, eth1 or wlan0 to count | packet capture 
    print("\n -- TCP ACKNOWLEDGE MONITOR --")
    print(f"Capturing {count} TCP packets...")
    print("-----------------------")

    def process_packet(packet):
        if packet.haslayer(IP) and packet.haslayer(TCP):
            src = packet[IP].src
            dst = packet[IP].dst
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            seq = packet[TCP].seq
            ack = packet[TCP].ack
            flags = packet[TCP].flags
            print(f"packet: {packet.summary()} ")

            print(
                f"{src}:{sport} -> "
                f"{dst}:{dport} | "
                f"Flags={flags} | "
                f"SEQ={seq} | "
                f"ACK={ack}"
            )

    sniff(
        iface=interface,
        filter="tcp",
        prn=process_packet,
        count=count

    )

    print("-------------------------------------")
    print("Capture finished.")
    print("=====================================")

# zenmap scan tool for network scanning and vulnerability assessment 
def run_zenmap_scan(target):
    return run_command(['zenmap', '-T', '4', '-A', target])


def get_ip_geolocation(ip):
    response = requests.get(f'http://ipinfo.io/{ip}/json')
    data = response.json()
    location = data.get('loc', 'N/A')
    city = data.get('city', 'N/A')
    region = data.get('region', 'N/A')
    country = data.get('country', 'N/A')
    return f"IP: {ip}\nLocation: {location}\nCity: {city}\nRegion: {region}\nCountry: {country}"

def check_emailaddress_platform(email):
    return run_command(['holehe', email])

def subfinder(domain):
    return run_command(['subfinder', '-d', domain, '-silent'])

# User-scanner tool combined Holehe (email scanning) and Sherlock (username scanning)
def use_scanner(email):
    return run_command(['user-scanner', '-e', email, '-v'])

def run_theharvester(domain: str):
    if not re.fullmatch(
        r"(?i)(?=.{1,253}$)"
        r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
        r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+",
        domain.strip()
    ):
        return "Invalid domain format."

    domain = domain.strip().lower()
    report_dir = Path("/Users/dr.saeedhamadalhassani/theHarvester")
    report_dir.mkdir(exist_ok=True)
    report_name = report_dir / f"harvester_{domain}"
    
    # Keeping your method structure ready if needed
    return f"Harvester prepared for {domain}"

# Blackbird tool from OSINT for email and username scanning and investigation  
def run_blackbird(email=None, username=None):
    cmd = ['python3', 'blackbird.py']
    
    if email:
        cmd.extend(['-e', email])
    if username:
        cmd.extend(['-u', username])
        
    _res = subprocess.run(
        cmd, 
        capture_output=True, 
        text=True, 
        cwd="/Users/dr.saeedhamadalhassani/blackbird"
    )
    
    return _res.stdout + _res.stderr

def exiftool(pic_path): # pic investigation + extract the metadata from the image file 
    return run_command(['exiftool', pic_path])


if __name__ == "__main__":
    choice = input("Start option to investigate (1 for -sV,\n 2 for -sS,\n 3 for sherlock search,\n 4 for domains Info \n 5 Dos Test \n 6 Nestat -an \n 7 DNS Lookup \n 8 Header inspection \n 9 check ssl\n 10 Email Investigators \n 11 check connectivity ((ping)) \n 12 Monitor Interface ACK \n 13 Zenmap scan \n 14 geolocation IP \n 15 holehe tool " \
    "\n 16 Subfinder tool \n 17 user-scanner : \n 18. theHarvester tool \n 19. Blackbird Investigation \n 20. ExifTool Image metadata extraction \n x. Exit \n ")
    
    if choice == "1" :
        entryip = input('Enter IP..')
        print(ip_info(entryip))

    elif choice == "2" :
        enterip = input("Enter IP..")
        print(dev_info(enterip))
    
    elif choice == "3":
        entername = input('Enter username to search.. ')
        print(get_info_sherlock(entername))

    elif choice == '4':
        enterdomain = input('Enter the domain name .. ')
        print(domain_whois(enterdomain))

    elif choice == '5':
        url = input('Enter URL: ')
        print(dos_attack(url))

    elif choice == '6':
        print(nestat())

    elif choice == '7':
        domain = input('enter domain to DNS lookup ')
        print(get_dns_info(domain))

    elif choice == '8':
        url = input("Enter URL to inspect headers: ")
        print(check_header(url))

    elif choice == '9':
        domain = input('Check ssl crt: ')
        print(check_ssl(domain))

    elif choice == '10':
        email = input('Enter specific email to find info about: ')
        print(mail_access(email))

    elif choice == '11':
        ip = input('Enter the IP to check connectivity: ')
        print(send_ping(ip))

    elif choice == '12':
        interface = input(
            "Enter network interface (press Enter for default): "
        ).strip()
        if interface == "":
            interface = None
        monitorack(interface)

    elif choice == '13':
        target = input('Enter the target to scan with Zenmap: ')
        print(run_zenmap_scan(target))

    elif choice == '14':
        ip = input('Enter the IP to get geolocation: ')
        print(get_ip_geolocation(ip))

    elif choice == '15':
        email = input('To investigate email through platforms: ')
        print(check_emailaddress_platform(email))

    elif choice == '16':
        domain = input('Enter the domain: ')
        print(subfinder(domain))

    elif choice == '17':
        email = input('Enter the email to use user-scanner tool: ')
        print(use_scanner(email))

    elif choice == "18":
        domain = input("Enter an authorized domain: ").strip()
        print(run_theharvester(domain))

    elif choice == '19':
        e_or_u = input('Enter email or username to apply Blackbird investigation process [-e] for email, [-u] for username: ')
        if e_or_u == '-e':
            email = input('Enter the email to investigate: ')
            print(run_blackbird(email=email))
        elif e_or_u == '-u':
            username = input('Enter username to investigate: ')
            print(run_blackbird(username=username))

    elif choice == '20':
        pic_path = input('Enter the path image to extraction metadata: ')
        print(exiftool(pic_path))

    elif choice.lower() == 'x':
        print(f'Nothing to do || see you again {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
    else:
        print("Invalid Choice || Try Again ")





# def run_theharvester(domain: str):
#     # Basic domain input validation
#     if not re.fullmatch(
#         r"(?i)(?=.{1,253}$)"
#         r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
#         r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+",
#         domain.strip()
#     ):
#         return "Invalid domain format."

#     domain = domain.strip().lower()

#     # Create a directory for investigation reports
#     report_dir = Path("/Users/dr.saeedhamadalhassani/theHarvester")
#     report_dir.mkdir(exist_ok=True)

#     report_name = report_dir / f"harvester_{domain}"

#     # command = [
#     #     "uv", "run", "--directory",
#     #     "/Users/dr.saeedhamadalhassani/theHarvester",
#     #     "theHarvester",
#     #     "-d", domain,
#     #     "-b", "crtsh,certspotter",
#     #     "-f", str(report_name)
#     # ]

#     # return run_command(['uv','run','theHarvester','-d',domain,'-b','crtsh,certspotter','-f',str(report_name)])
# #uv run theHarvester -d example.com -b crtsh,certspotter
    
# #Blackbird tool from OSINT for email and username scanning and investigation  
