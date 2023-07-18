import shutil
import subprocess
import os

#check tool installation status
def check_tools():
    pass

def scan_for(subdomain_tool_command,output_file):
    output=subprocess.check_output(subdomain_tool_command,shell=True)
    output_file.writelines(output.decode("utf-8"))

def make_uniq_file(subfile):
    pass

#subdomain discovery
def subdomain_discovery(domain):
    global new_directory

    new_directory=f"{domain}_adbeautifier_scan"

    if os.path.exists(new_directory):
        shutil.rmtree(new_directory)
    
    try:
        os.makedirs(new_directory)
        print(f"Directory {new_directory} created successfully.")
    except OSError as e:
        print(f"Error creating directory: {e}")
    subfile=open(f"{new_directory}/{domain}_subdomains.txt","a")

    subfinder_command=f"subfinder -d {domain} -silent -nW" + "| awk '/Enumerating subdomains/ {found=1; next} found { print}' "
    amass_command=f"amass enum -passive -d {domain}"
    theharvester_command=f"theHarvester -d {domain} -b all "+"| awk '/Hosts found:/ { found=1; next } found { print }'| awk -F ':' '{print $1}' |awk '($0 ~ /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/)'|uniq "
    
    print("Subfinder scanning [+]")
    scan_for(subfinder_command,subfile)
    print("Amass scanning [+]")
    scan_for(amass_command,subfile)
    print("TheHarvester scanning [+]")
    scan_for(theharvester_command,subfile)
    subfile.close()    
    print("Subdomain discovery completed")

    uniq_file=subprocess.check_output(f"sort {new_directory}/{domain}_subdomains.txt | uniq",shell=True)
    subfile=open(f"{new_directory}/{domain}_subdomains.txt","w")
    subfile.writelines(uniq_file.decode("utf-8"))
    print(f"File operations were finished, {new_directory}/{domain}_subdomains.txt")
    
#ping domains
def ping_subdomains(domain):
    with open(f"{new_directory}/{domain}_subdomains.txt", "r") as subfile:
        subdomains = subfile.read().splitlines()

    subdomains_with_ip = []
    with open(f"{new_directory}/subswithip.txt", "w") as subswithip_file:
        for subdomain in subdomains:
            ping_command = f"dig +short {subdomain}"
            try:
                ping_output = subprocess.check_output(ping_command, shell=True)
                ip_address = ping_output.decode('utf-8').strip()
                if ip_address:
                    subdomains_with_ip.append(f"{subdomain}: {ip_address}")
                    subswithip_file.write(f"{subdomain}: {ip_address}\n")
                    print(f"{subdomain} is reachable. Response: {ip_address}")
                else:
                    print(f"{subdomain} is not reachable.")
            except subprocess.CalledProcessError as e:
                print(f"{subdomain} is not reachable. Error: {e}")