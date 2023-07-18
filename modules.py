import subprocess

#check tool installation status
def check_tools():
    pass

def scan_for(subdomain_tool_command,output_file):
    output=subprocess.check_output(subdomain_tool_command,shell=True)
    output_file.writelines(output.decode("utf-8"))

def make_uniq_file(subfile):
    pass

#subdomain discovery



