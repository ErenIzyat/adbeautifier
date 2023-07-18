import subprocess

#subdomain discovery
def subdomain_discovery(domain):
    subfinder_command=f"subfinder -d {domain} -nW"
    print("Scanning begin")
    output=subprocess.check_output(subfinder_command,shell=True)
    
    subfile=open("subds.txt","w")
    subfile.writelines(output.decode("utf-8"))
    subfile.close()
#ping domains
def ping_subdomains():
    with open("subds.txt", "r") as subfile:
        subdomains = subfile.read().splitlines()

    subdomains_with_ip = []
    with open("subswithip.txt", "w") as subswithip_file:
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