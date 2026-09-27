# Version 1.1 

from url_scanner import analyze_urls


def analyze_email(email):
    score = 0
    findings = []

    suspicious_phrases = [
        "urgent",
        "verify your account",
        "password",
        "click here",
        "account suspended",
        "immediately"
    ]

    email_lower = email.lower()

    # Analyze email language
    for phrase in suspicious_phrases:
        if phrase in email_lower:
            findings.append(
                f"Suspicious phrase found: {phrase}"
            )
            score += 10

    # Analyze URLs
    url_findings, url_score = analyze_urls(email)

    findings.extend(url_findings)
    score += url_score

    # Keep score between 0 and 100
    score = min(score, 100)

    print("\n==============================")
    print("       PHISHLENS REPORT")
    print("==============================")

    if findings:
        for finding in findings:
            print("\n[!] " + finding)
    else:
        print("[+] No obvious phishing indicators detected.")

    print("\nRisk Score:", str(score) + "/100")

    if score >= 60:
        print("Risk Level: HIGH")
    elif score >= 30:
        print("Risk Level: MEDIUM")
    else:
        print("Risk Level: LOW")

    print("==============================")