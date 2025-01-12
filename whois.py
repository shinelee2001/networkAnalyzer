# whois.py

import subprocess

def whois(ip):
    """
    Executes a WHOIS query for the given IP address using the 'whois' command.
    """
    try:
        result = subprocess.run(["whois", ip], capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout.strip()
        else:
            return "Failed to retrieve WHOIS information."
    except Exception as e:
        return f"Error: {str(e)}"
