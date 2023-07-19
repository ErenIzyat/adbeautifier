import shutil
import subprocess
import os
import ipwhois

# check tool installation status
def check_tools():
    pass

def scan_for(subdomain_tool_command, output_file):
    output = subprocess.check_output(subdomain_tool_command, shell=True)
    output_file.writelines(output.decode("utf-8"))

def make_uniq_file(subfile):
    pass

# subdomain discovery
def subdomain_discovery(domain):
    global new_directory

    new_directory = f"{domain}_adbeautifier_scan"

    if os.path.exists(new_directory):
        shutil.rmtree(new_directory)

    try:
        os.makedirs(new_directory)
        print(f"Directory {new_directory} created successfully.")
    except OSError as e:
        print(f"Error creating directory: {e}")
    subfile = open(f"{new_directory}/{domain}_subdomains.txt", "a")

    subfinder_command = f"subfinder -d {domain} -silent -nW" + "| awk '/Enumerating subdomains/ {found=1; next} found { print}' "
    amass_command = f"amass enum -passive -d {domain}"
    theharvester_command = f"theHarvester -d {domain} -b all " + "| awk '/Hosts found:/ { found=1; next } found { print }'| awk -F ':' '{print $1}' |awk '($0 ~ /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/)'|uniq "

    print("Subfinder scanning [+]")
    scan_for(subfinder_command, subfile)
    print("Amass scanning [+]")
    scan_for(amass_command, subfile)
    print("TheHarvester scanning [+]")
    scan_for(theharvester_command, subfile)
    subfile.close()
    print("Subdomain discovery completed")

    uniq_file = subprocess.check_output(f"sort {new_directory}/{domain}_subdomains.txt | uniq", shell=True)
    subfile = open(f"{new_directory}/{domain}_subdomains.txt", "w")
    subfile.writelines(uniq_file.decode("utf-8"))
    print(f"File operations were finished, {new_directory}/{domain}_subdomains.txt")

# ping subdomains
def ping_subdomains(domain):
    # Keşfedilen subdomainlerin IP adreslerini kontrol eder ve sonuçları dosyaya yazar.
    with open(f"{new_directory}/{domain}_subdomains.txt", "r") as subfile:
        subdomains = subfile.read().splitlines()
        

    subdomains_with_unique_ip = {}
    for subdomain in subdomains:
        dnsx_command = f'dnsx -l "{new_directory}/{domain}_subdomains.txt" -a -silent -resp '
        try:
            dnsx_output = subprocess.check_output(dnsx_command, shell=True)
            dnsx_output = dnsx_output.decode('utf-8').strip()
           #dnsx çıktısını split ediyoruz.
            dnsx_data = dnsx_output.split()
            if len(dnsx_data) >= 2:
                ip_address_dnsx = dnsx_data[-1]
                if ip_address_dnsx and (subdomain, ip_address_dnsx) not in subdomains_with_unique_ip.values():
                    subdomains_with_unique_ip[subdomain] = ip_address_dnsx
                    print(f"{subdomain} is reachable. Response: {ip_address_dnsx}")
                else:
                    print(f"{subdomain} isn't reachable.")
            else:
                print(f"{subdomain} isn't reachable")
        except subprocess.CalledProcessError:
            print(f"{subdomain} isn't reachable.")

   
    with open(f"{new_directory}/{domain}_subswithip.txt", "w") as subswithip_file:
        for subdomain, ip_address in subdomains_with_unique_ip.items():
       
            subswithip_file.write(f"{subdomain}: {ip_address.strip('[]')}\n")
    print("Dnsx scannig [+]")

def get_cdn(ip_address):
    try:
        description = ipwhois.IPWhois(ip_address).lookup_whois()["nets"][0]["description"]
        return description
    except Exception as e:
        return f"Error: {e}"

      
def get_pureip(domain):
    
    ip_addresses = []

    with open(f"{new_directory}/{domain}_subswithip.txt", "r") as file:
        for line in file:
            subdomain, ip_address = line.strip().split(":")
            ip_addresses.append(ip_address.strip())

    for ip_address in ip_addresses:
        description = get_cdn(ip_address)
        print(f"{ip_address}: {description}")

    non_cloudflare_ips = []

    for ip_address in ip_addresses:
        description = get_cdn(ip_address)
        if "cloudflare" not in description.lower() and "amazon" not in description.lower():
            non_cloudflare_ips.append(ip_address)

    with open(f"{new_directory}/{domain}_naabuip.txt", "w") as output_file:
        for ip in non_cloudflare_ips:
            output_file.write(f"{ip}\n")

def port_scan(domain):
    
    naabu_command = f'naabu -silent -l "{new_directory}/{domain}_naabuip.txt" -o "{new_directory}/{domain}_naabuscan.txt" -nmap-cli "nmap -sV -Pn -oX {new_directory}/{domain}_nmapscan"'

    # Run the naabu command
    try:
        os.system(naabu_command)
        print("Port scanning completed.")
    except Exception as e:
        print(f"Error during port scanning: {e}")
        

        