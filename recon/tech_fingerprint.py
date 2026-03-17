import subprocess

def run(target):
    try:
        cmd = ["whatweb", target]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )
        return result.stdout
    except Exception as e:
        return f"Error during technology fingerprinting: {e}"
