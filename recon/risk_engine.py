def calculate_risk(results_dict):
    score = 0

    # Subdomain risk
    subdomains = results_dict.get("Subdomain Enumeration", "")
    if len(subdomains.splitlines()) > 50:
        score += 2

    # Port risk
    ports_output = results_dict.get("Port Scanning", "")
    sensitive_ports = ["22", "3306", "5432", "6379", "5060"]
    for port in sensitive_ports:
        if port in ports_output:
            score += 3

    # Directory risk
    dir_output = results_dict.get("Directory Enumeration", "")
    if "No directories found" not in dir_output:
        score += 3

    # CDN reduces risk
    tech_output = results_dict.get("Technology Fingerprinting", "")
    if "cloudflare" in tech_output.lower():
        score -= 1

    # Final classification
    if score <= 2:
        return "LOW", score
    elif score <= 5:
        return "MEDIUM", score
    else:
        return "HIGH", score
