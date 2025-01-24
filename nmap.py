# nmap.py

import subprocess

def nmap(ip):
    """
    Executes a WHOIS query for the given IP address using the 'whois' command.
    """
    try:
        result = subprocess.run(["nmap", ip, "-O"], capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout.strip()
        else:
            return "Failed to retrieve WHOIS information."
    except Exception as e:
        return f"Error: {str(e)}"
