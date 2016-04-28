import subprocess, re

def get_windows_default_dns():
    output = subprocess.Popen(["netsh", "interface", "ipv4", "show", "dns"], stdout=subprocess.PIPE).communicate()[0]
    re_ipv4 = re.compile("(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", re.MULTILINE)
    match_obj = re_ipv4.search(output)
    if match_obj:
        return match_obj.group(0)