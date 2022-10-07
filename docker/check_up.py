from sys import argv, exit, stderr
from os import system, name

if len(argv) == 2:
    ip = argv[1].replace(";", "").replace("&", "").replace("\n", "")
else:
    print("USAGES: python3 check_up.py <target ip or hostname>", file="stderr")
    exit(1)

if name == "nt":
    option = "-n"
    arp_command = f'arp -a | findstr "{ip}"'
else:
    option = "-c"
    arp_command = f'cat /proc/net/arp | grep "{ip}"'

system(f"ping {option} 1 {ip}")

if system(arp_command):
    print(ip, "is down.")
    exit(2)
else :
    print(ip, "is up.")
    exit(0)