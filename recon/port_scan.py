import subprocess

def run(target):
    command = [
        "nmap",
        "-T4",           # faster timing
        "--top-ports", "1000",
        "-Pn",           # skip host discovery (already done)
        target
    ]
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=300
    ).stdout


#   def run(target):
#     try:
#         cmd = ["nmap", "-sS", "-T4", target]
#         result = subprocess.run(
#             cmd,
#             capture_output=True,
#             text=True,
#             timeout=300
#         )
#         return result.stdout
#     except Exception as e:
#         return f"Error during port scanning: {e}"
