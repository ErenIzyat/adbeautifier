import shutil
import subprocess
import os

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

# ping domains
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

            # dnsx çıktısını doğru formata dönüştürelim
            dnsx_data = dnsx_output.split()
            if len(dnsx_data) >= 2:
                ip_address_dnsx = dnsx_data[-1]
                if ip_address_dnsx and (subdomain, ip_address_dnsx) not in subdomains_with_unique_ip.values():
                    subdomains_with_unique_ip[subdomain] = ip_address_dnsx
                    print(f"{subdomain} erişilebilir (dnsx). Cevap: {ip_address_dnsx}")
                else:
                    print(f"{subdomain} erişilebilir değil (dnsx).")
            else:
                print(f"{subdomain} erişilebilir değil (dnsx).")
        except subprocess.CalledProcessError:
            print(f"{subdomain} erişilebilir değil (dnsx).")

    # Alt alan adlarını ve eşsiz IP adreslerini dosyaya yazdıralım
    with open(f"{new_directory}/{domain}_subswithip.txt", "w") as subswithip_file:
        for subdomain, ip_address in subdomains_with_unique_ip.items():
            # Parantezleri kaldırarak yazdırma işlemi
            subswithip_file.write(f"{subdomain}: {ip_address.strip('[]')}\n")
