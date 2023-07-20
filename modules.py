import csv
import shutil
import subprocess
import os
import ipwhois
import openpyxl
import pandas as pd
import xml.etree.ElementTree as ET
import glob

# check tool installation status
def check_tools():
    pass

def scan_for(subdomain_tool_command, output_file):
    output = subprocess.check_output(subdomain_tool_command, shell=True)
    output_file.writelines(output.decode("utf-8"))

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
        
    print("Dnsx scannig [+]")
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
                    print(f"{subdomain} is reachable. Response: \033[32m{ip_address_dnsx}\033[0m")
                else:
                    print(f"{subdomain} isn't reachable.")
            else:
                print(f"{subdomain} isn't reachable")
        except subprocess.CalledProcessError:
            print(f"{subdomain} isn't reachable.")

   
    with open(f"{new_directory}/{domain}_subswithip.txt", "w") as subswithip_file:
        for subdomain, ip_address in subdomains_with_unique_ip.items():
       
            subswithip_file.write(f"{subdomain}: {ip_address.strip('[]')}\n")
    

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
        
#httpx scanning
def find_websites(domain):
    
    split_command="awk -F ':' '{print $1}' "+f"{new_directory}/{domain}_subswithip.txt"
    subs=subprocess.run(split_command,shell=True,capture_output=True).stdout.decode("utf-8").strip()
    with open(f"{new_directory}/{domain}_naabuscan.txt","a") as input:
        input.writelines(subs)
        
    httpx_command=f"~/go/bin/httpx -list {new_directory}/{domain}_naabuscan.txt -silent"
    print("httpx scanning [+]")
    try:
        httpx_output=subprocess.run(httpx_command,shell=True,capture_output=True)
        print(httpx_output.stdout.decode("utf-8").strip())
        with open(f"{new_directory}/{domain}_websites.txt","w") as website_file:
            website_file.writelines(httpx_output.stdout.decode("utf-8").strip())
    
    except:
        print(httpx_output.stderr)
def nmap_xml_to_csv(xml_file, csv_file):
    # Parse the XML file
    tree = ET.parse(xml_file)
    root = tree.getroot()

    # Open a CSV file for writing
    with open(csv_file, 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)

        # Write the header row
        # header = ['IP', 'Hostname', 'Port', 'Service']
        # csv_writer.writerow(header)

        # Write the data rows
        for host in root.findall('.//host'):
            ip_address = host.find('.//address[@addrtype="ipv4"]').attrib['addr']
            hostname = host.find('.//hostname').attrib.get('name', '')
            for port in host.findall('.//port'):
                port_number = port.attrib['portid']
                service = port.find('.//service').attrib['name']
                csv_writer.writerow([ip_address, hostname, port_number, service])        


def create_table(input_files, output_file):
    emptydata = {"": []}
    df_blank = pd.DataFrame(emptydata)
    df0 = pd.read_csv(input_files[0], header=None, names=['Domain'])
    df1 = pd.read_csv(input_files[1], delimiter=':', header=None, names=['Subdomain', 'IP'])

    port_list = []
    with open(input_files[2], "r") as file:
        for line in file:
            line = line.strip()
            if ":" in line:
                port_list.append(line)

    df2 = pd.DataFrame({'Port': port_list})
    df3 = pd.read_csv(input_files[3], header=None, names=['Website'])
    if len(input_files)==5:
        df4=pd.read_csv(input_files[4],delimiter=",",header=None,names=['IP','Hostname','Port','Service'])
        merged_data = pd.concat([df0,df1,df2,df3,df_blank,df_blank,df4], axis=1)
    else:
        merged_data = pd.concat([df0,df1,df2,df3], axis=1)

    # Save the merged data to a CSV file
    merged_data.to_csv(output_file, index=False)

def convert_csv_to_xlsx(input_csv, output_xlsx):
    # Read the CSV file
    df = pd.read_csv(input_csv)
    

    # Save the dataframe to an Excel file
    df.to_excel(output_xlsx, index=False)


def make_report(domain):
    new_directory = f"{domain}_adbeautifier_scan"
    if type(domain) is str:
        print("Creating asset discovery report [+]")
        with open(f"{new_directory}/target.txt", "w") as t:
            t.write(domain)
        if os.path.exists(f"{new_directory}/{domain}_nmapscan"):
            nmap_xml_to_csv(f"{new_directory}/{domain}_nmapscan",f"{new_directory}/nmapscan.csv")
            input_files = [f"{new_directory}/target.txt",f"{new_directory}/{domain}_subswithip.txt",  f"{new_directory}/{domain}_naabuscan.txt",f"{new_directory}/{domain}_websites.txt",f"{new_directory}/nmapscan.csv"]
        else:
            input_files = [f"{new_directory}/target.txt",f"{new_directory}/{domain}_subswithip.txt",  f"{new_directory}/{domain}_naabuscan.txt",f"{new_directory}/{domain}_websites.txt"]

        output_csv = f"{domain}_report.csv"
        output_xlsx = f"{domain}_report.xlsx"

        create_table(input_files, output_csv)
        convert_csv_to_xlsx(output_csv, output_xlsx)

        # Sütun genişliklerini ayarlama
        workbook = openpyxl.load_workbook(output_xlsx)
        sheet = workbook.active
        sheet.column_dimensions['A'].width = 25
        sheet.column_dimensions['B'].width = 25
        sheet.column_dimensions['C'].width = 25
        sheet.column_dimensions['D'].width = 25
        sheet.column_dimensions['E'].width = 25
        sheet.column_dimensions['F'].width = 25
        sheet.column_dimensions['G'].width = 25
        sheet.column_dimensions['H'].width = 25
        sheet.column_dimensions['I'].width = 25
        sheet.column_dimensions['J'].width = 25
        sheet.column_dimensions['K'].width = 25
        
        workbook.save(output_xlsx)

        
    # else:
    #     with open("targets.txt", "w") as ds:
    #         ds.writelines(domain)
    #     print("Couldnt create report for multiple target domains for now")

def merge_reports():

    # Get a list of all CSV files in the directory
    csv_files = glob.glob("*.csv")

    # Initialize an empty DataFrame to store the merged data
    merged_df = pd.DataFrame()

    # Read each CSV file and merge it into the main DataFrame
    for csv_file in csv_files:
        df = pd.read_csv(csv_file)
        merged_df = pd.concat([merged_df, df], ignore_index=True)

    # Save the merged DataFrame to a new CSV file
    #merged_df=merged_df.apply(lambda x: x.str.strip() if x.dtype == "object" else x)
    merged_df.to_csv("general_report.csv", index=False)

    print("CSV files merged successfully.")