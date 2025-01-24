# myip.py

import subprocess
import platform

def get_interface_ip(interface):
    """
    Get the IP address of the specified network interface using platform-specific commands.
    """
    system_platform = platform.system().lower()

    try:
        if system_platform == "windows":
            result = subprocess.run(["ipconfig"], capture_output=True, text=True)
            if result.returncode == 0:
                # Extract the IP address associated with the specified interface
                for line in result.stdout.splitlines():
                    if interface in line:
                        # Check the following lines for IPv4 address
                        next_lines = iter(result.stdout.splitlines())
                        for l in next_lines:
                            if "IPv4 Address" in l or "IPv4" in l:
                                return l.split(":")[1].strip()
            return f"Error: Could not find IP for {interface} on Windows."

        elif system_platform == "linux":
            result = subprocess.run(["ifconfig", interface], capture_output=True, text=True)
            if result.returncode == 0:
                # Extract the IP address from the output of `ifconfig`
                for line in result.stdout.splitlines():
                    if "inet " in line:
                        return line.split()[1]
            # Fallback: try `ip a` command
            result = subprocess.run(["ip", "a", "show", interface], capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if "inet " in line:
                        return line.split()[1]
            return f"Error: Could not find IP for {interface} on Linux."

        else:
            return f"Error: Unsupported platform {system_platform}."

    except Exception as e:
        return f"Error: Could not retrieve IP address for {interface}. {e}"
