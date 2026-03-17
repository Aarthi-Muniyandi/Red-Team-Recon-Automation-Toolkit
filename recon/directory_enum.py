import subprocess

def run(target):
    try:
        cmd = [
            "gobuster", "dir",
            "-u", f"http://{target}",
            "-w", "/usr/share/wordlists/dirb/common.txt",
            "-q"
        ]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )
        return result.stdout if result.stdout else "No directories found."
    except Exception as e:
        return f"Error during directory enumeration: {e}"
