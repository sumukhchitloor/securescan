import subprocess
import re
import os
import socket
import argparse
import paramiko
import telnetlib3
import ftplib
import threading
import os
import time
import json
import requests
from nvd_api import NvdApiClient
from pprint import pprint
from nvd_api.low_api.exceptions import NotFoundException
from halo import Halo

def check_os_vulns():
    spinner = Halo(text="Scanning for Debian packages vulnerabilities", spinner="dots")
    spinner.start()

    # Run command to get list of installed packages
    packages_command = "dpkg -l"
    packages_process = subprocess.Popen(packages_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    packages_output = packages_process.stdout.read().decode()

    # Parse list of installed packages
    packages = {}
    for line in packages_output.split("\n")[5:]:
        parts = line.split()
        if len(parts) > 1:
            package_name = parts[1]
            package_version = parts[2]
            cves = []
            # Use NVD API to search for CVEs based on package name and version
            client = NvdApiClient()
            try:
                cve_details = client.get_cves(
                    cpe_name=f"cpe:2.3:o:{package_name}:{package_version}:*:*:*:*:*:*:*",
                    results_per_page=1,
                    start_index=1
                )
                if cve_details:
                    cve_id = cve_details["cve"]["CVE_data_meta"]["ID"]
                    cve_description = cve_details["cve"]["description"]["description_data"][0]["value"]
                    cves.append((cve_id, cve_description))
                # Add package and associated CVEs to dictionary
                packages[package_name] = {"version": package_version, "cves": cves}
            except NotFoundException:
                pass

    # Print out the vulnerable packages and their associated CVEs
    if packages:
        print("[+]The following packages are vulnerable:")
        for package_name, cves in vulnerable_packages.items():
            print(f"{package_name}:")
            for cve in cves:
                print(f"\t{cve.cve_id} - {cve.summary}")
    else:
        print("[-] No vulnerable Debian packages found.")
    
    # Stop the spinner
    spinner._stop()

# Function to fetch CVEs from NVD API
def fetch_cves(name, version):
    cves = []
    try:
        client = NvdApiClient()
        # cve_items = api_client.cve_query(search_param=f"cpe:/a:{name}:{version}")
        cve_items = client.get_cves(
            cpe_name="cpe:2.3:o:{name}:{version}:*:*:*:*:*:*:*",
            cvss_v2_metrics="AV:L/AC:L/Au:N/C:C/I:C/A:C",
            cvss_v2_severity="HIGH",
            results_per_page=1,
            start_index=1)
        print(cpe_name)
        pprint(cve_items)
        for cve_item in cve_items:
            cve_id = cve_item.id
            cve_description = cve_item.description
            cves.append((cve_id, cve_description))
        return cves
    except NotFoundException :
        pass

# Function to scan for vulnerabilities
def scan_vulnerabilities(targets):
    spinner = Halo(text="Scanning for vulnerabilities on open port softwares\n", spinner="dots")
    spinner.start()
    vulnerable_hosts = []
    nmap_output = os.popen("nmap -sS -sV " + targets).read()
    for line in nmap_output.splitlines():
        match = re.match(r"(\d+)/tcp\s+open\s+(\S+)\s+(.*)", line)
        if match:
            port = match.group(1)
            software = match.group(2)
            version = match.group(3)
            # Fetch associated CVEs from NVD API
            cves = fetch_cves(software, version)
            if cves is not None and len(cves) > 0:
                spinner.succeed("\tVulnerable software found on " + targets + ":" + port)
                for cve in cves:
                    spinner.info("CVE: " + cve[0])
                    spinner.info("Description: " + cve[1])
                vulnerable_hosts.append((targets, port, software, version))
            else:
                spinner.info("\tSoftware (" + version +") on the port " + port + " is latest and secured\n")
    spinner.stop()            
    return vulnerable_hosts

def check_port(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    result = sock.connect_ex((ip, port))
    if result == 0:
        print(f"[+] Port {port} is open on {ip}")
        if port == 22:
            brute_force_ssh(ip)
        elif port == 23:
            brute_force_telnet(ip)
        elif port == 21:
            brute_force_ftp(ip)
        try:
            service = socket.getservbyport(port)
        except:
            service = "unknown"
        print(f"Software running on port {port}: {service}")
        print("")
    sock.close()

def brute_force_ssh(ip):
    try:
        subprocess.run(['hydra', '-h'], capture_output=True, text=True)
    except FileNotFoundError:
        # If hydra is not installed, install it using apt-get
        print('Hydra is not installed, installing now...')
        subprocess.run(['sudo', 'apt-get', 'update'])
        subprocess.run(['sudo', 'apt-get', 'install', 'hydra'])

    user_file = 'user.txt'
    pass_file = 'passwords.txt'
    ip_address = ip
    hydra_args = ['hydra', '-L', user_file, '-P', pass_file, ip_address, 'ssh', '-t', '4']
    result = subprocess.run(hydra_args, capture_output=True, text=True)
    print(result.stdout)

def brute_force_telnet(ip):
    print("Trying to brute force Telnet...")
    user_file = 'user.txt'
    pass_file = 'passwords.txt'
    with open(user_file) as u:
        users = u.readlines()
    with open(pass_file) as p:
        passwords = p.readlines()
    for user in users:
        for password in passwords:
            try:
                tn = telnetlib.Telnet(ip, timeout=2)
                tn.read_until(b"login: ")
                tn.write(user.encode('ascii') + b"\n")
                tn.read_until(b"Password: ")
                tn.write(password.encode('ascii') + b"\n")
                result = tn.read_some().decode('ascii')
                if "Login incorrect" not in result:
                    print(f"Found valid Telnet credentials for {ip}: {user.strip()} / {password.strip()}")
                    tn.write(b"exit\n")
                    tn.close()
                    return
                tn.close()
            except:
                pass

def brute_force_ftp(ip):
    print("Trying to brute force FTP...")
    user_file = 'user.txt'
    pass_file = 'passwords.txt'
    with open(user_file) as u:
        users = u.readlines()
    with open(pass_file) as p:
        passwords = p.readlines()
    for user in users:
        for password in passwords:
            try:
                ftp = ftplib.FTP(ip, timeout=2)
                ftp.login(user.strip(), password.strip())
                print(f"Found valid FTP credentials for {ip}: {user.strip()} / {password.strip()}")
                ftp.quit()
                return
            except:
                pass
def kernel_vulnerability_check():
    try:
        kernel_version = os.uname().release

        # Query NVD API for vulnerabilities related to the kernel version
        client = NvdApiClient()
        # cve_items = api_client.cve_query(search_param=f"cpe:/a:{name}:{version}")
        cve_items = client.get_cves(
            cpe_name="linux%20kernel%20{kernel_version}",
            cvss_v2_metrics="AV:L/AC:L/Au:N/C:C/I:C/A:C",
            cvss_v2_severity="HIGH",
            results_per_page=1,
            start_index=1)
        print(cpe_name)
        pprint(cve_items)
        for cve_item in cve_items:
            cve_id = cve_item.id
            cve_description = cve_item.description
            cves.append((cve_id, cve_description))
        return cves

    except NotFoundException:
        print("Linux kernel is in latest version")

# Check for previlage escalation
def check_privilege_escalation():
    spinner = Halo(text="Checking for any previlage escalation\n", spinner="dots")
    spinner.start()
    time.sleep(4)
    spinner.stop()
    os.system("bash priv_esc.sh")

# Test the function
def main(target, threads):
    for port in range(1,65536):
        check_port(target, port)
    check_os_vulns()
    kernel_vulnerability_check()
    check_privilege_escalation()
    threads_list = []

    for i in range(threads):
        t = threading.Thread(target=scan_vulnerabilities, args=(target,))
        threads_list.append(t)
        t.start()

    for t in threads_list:
        t.join()
    vulnerable_hosts=scan_vulnerabilities(target)
    if len(vulnerable_hosts) == 0:
        print(f"No vulnerabilities found on {target}")
    else:
        print(f"Vulnerabilities found on {vulnerable_hosts} on {target}")


if __name__ == "__main__":
    try:
        print('''
 __                          __                 
/ _\ ___  ___ _   _ _ __ ___/ _\ ___ __ _ _ __  
\ \ / _ \/ __| | | | '__/ _ \ \ / __/ _` | '_ \ 
_\ \  __/ (__| |_| | | |  __/\ \ (_| (_| | | | |
\__/\___|\___|\__,_|_|  \___\__/\___\__,_|_| |_|
                                                
''')
        parser = argparse.ArgumentParser(description="Scan for vulnerabilities",epilog="Example: sudo scanner.py -T4 192.168.0.1")
        parser.add_argument("target", type=str, nargs="?", help="Target IP or URL")
        parser.add_argument("-T", "--threads", type=int, default=1, help="Number of threads to use (default: 1)")
        args = parser.parse_args()

        if args.target:
            main(args.target, args.threads)
        else:
            print("Please specify a target.")
    except KeyboardInterrupt:
        time.sleep(1)
        print("\nKeyboard Interrupted: Quitting")