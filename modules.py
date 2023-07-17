import subprocess

#subdomain discovery
def subdomain_discovery(domain):
    subfinder_command=f"subfinder -d {domain} -nW"
    print("Scanning begin")
    output=subprocess.check_output(subfinder_command,shell=True)
    
    subfile=open("subds.txt","w")
    subfile.writelines(output.decode("utf-8"))
    subfile.close()
