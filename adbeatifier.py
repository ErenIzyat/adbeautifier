import argparse
from modules import subdomain_discovery
from modules import ping_subdomains

def main():
    parser=argparse.ArgumentParser(description="Asset Discovery Automatizotion Tool",usage="python3 adbeautifier.py -d domain/-D domain/file/path")
    parser.add_argument("--domain","-d",type=str,help="Scan for a domain")
    parser.add_argument("--domains","-D",type=argparse.FileType('r'),help="Scan for a given domain file")
    
    args = parser.parse_args()

    if args.domain:
        target=args.domain
        subdomain_discovery(target)
        ping_subdomains(target)
        
    if args.domains:
        #print("input file: ", args.domains.name)
        for line in args.domains:
            pass
            #print(line.strip())
    

if __name__ == "__main__":
    main()