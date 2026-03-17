import subprocess

def run(target):
    try:
        cmd = ["nmap", "-sn", target]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )
        return result.stdout
    except Exception as e:
        return f"Error during live host detection: {e}"
