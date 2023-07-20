import argparse
from modules import make_report, subdomain_discovery,ping_subdomains,get_pureip,port_scan,find_websites,merge_reports
import subprocess
import os
class color:
    default = '\033[0m'
    cyan='\033[36m'
    red='\033[31m'
    purple='\033[95m'
    lightgrey='\033[37m'
    yellow='\033[93m'
    green="\033[32m"

def banner(args=False):
    subprocess.call('clear', shell=True)
    print(color.cyan+"""                  .o8   .o8                                           .    o8o   .o88o.  o8o                     
               "888  "888                                         .o8    `"'   888 `"  `"'                     
 .oooo.    .oooo888   888oooo.   .ooooo.   .oooo.   oooo  oooo  .o888oo oooo  o888oo  oooo   .ooooo.  oooo d8b 
`P  )88b  d88' `888   d88' `88b d88' `88b `P  )88b  `888  `888    888   `888   888    `888  d88' `88b `888""8P 
 .oP"888  888   888   888   888 888ooo888  .oP"888   888   888    888    888   888     888  888ooo888  888     
d8(  888  888   888   888   888 888    .o d8(  888   888   888    888 .  888   888     888  888    .o  888     
`Y888""8o `Y8bod88P"  `Y8bod8P' `Y8bod8P' `Y888""8o  `V88V"V8P'   "888" o888o o888o   o888o `Y8bod8P' d888b                                                                                                                                                     
 """+ color.default)
    print("                  Automated asset discovery tool          ")
    print("                      A project by "+color.red+"arzu-eren              "+ color.default)
    print()
    if(args and not args.domain and not args.domains):
        print("You can use\n" + color.cyan + "python adbeautifier.py -d domain" +color.default)
        print(color.cyan+ "python adbeautifier.py -D domainfile.txt\n"+color.default )
        print("Check other options:" + color.cyan + "adbeautifier -h" +color.default)
    print()

def main():
    parser=argparse.ArgumentParser(description="Asset Discovery Automatizotion Tool",usage="python3 adbeautifier.py -d domain/-D domain/file/path")
    parser.add_argument("--domain","-d",type=str,help="Scan for a domain")
    parser.add_argument("--domains","-D",type=argparse.FileType('r'),help="Scan for a given domain file")
    parser.add_argument("--no-banner","-nb",type=None,help="Hide the banner")
    
    args = parser.parse_args()
    banner(args)
    if args.domain:
        target=args.domain
        subdomain_discovery(target)
        ping_subdomains(target)
        get_pureip(target)
        port_scan(target)
        find_websites(target)
        make_report(target)
        
        
    if args.domains:
        main_dir="adbeautifier_scan_logs"
        try:
            os.makedirs(main_dir)
            print(f"Main directory '{main_dir}' created successfully.")
        except OSError as e:
            print(f"Error creating directory: {e}")
        try:
            os.chdir(main_dir)
        except OSError as e:
            print(f"Hata: {e}")

        for target_domain in args.domains:
            print(f"*****************\033[93mTarget domain: {target_domain.strip()}\033[0m**************")
            subdomain_discovery(target_domain.strip())
            ping_subdomains(target_domain.strip())
            get_pureip(target_domain.strip())
            port_scan(target_domain.strip())
            find_websites(target_domain.strip())   
            make_report(target_domain.strip())
        print("Merging reports [+]")
        merge_reports()

if __name__ == "__main__":
    main()
    print("Asset discovery completed .")