import subprocess

def run(target):
    try:
        cmd = ["subfinder", "-d", target, "-silent"]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )
        return result.stdout if result.stdout else "No subdomains found."
    except Exception as e:
        return f"Error during subdomain enumeration: {e}"
