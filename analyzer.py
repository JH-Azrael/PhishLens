#Version 1.0 
#Author Jonathan Hall, Samuel Remp, Cole Crandall

def analyze_email(email):
    score = 0
    findings = []

    suspicious_words = [
        "urgent",
        "verify your account",
        "password",
        "click here",
        "account suspended",
        "immediately"
    ]

    email_lower = email.lower()

    for word in suspicious_words:
        if word in email_lower:
            findings.append("Suspicious phrase found: " + word)
            score += 10

    print("\n--- PhishLens Report ---")

    for finding in findings:
        print("[!] " + finding)

    print("\nRisk Score:", score)

    if score >= 40:
        print("Risk Level: HIGH")
    elif score >= 20:
        print("Risk Level: MEDIUM")
    else:
        print("Risk Level: LOW")