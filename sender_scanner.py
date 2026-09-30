#Jonathan Hall 
#Created for Version 1.2


import re


TRUSTED_ORGANIZATIONS = {
    "microsoft": [
        "microsoft.com",
        "microsoftonline.com"
    ],
    "google": [
        "google.com"
    ],
    "paypal": [
        "paypal.com"
    ],
    "amazon": [
        "amazon.com"
    ],
    "apple": [
        "apple.com"
    ],
    "rit": [
        "rit.edu"
    ]
}


def extract_sender(email):
    pattern = r"From:\s*(.*?)\s*<([^>]+)>"
    match = re.search(pattern, email, re.IGNORECASE)

    if match:
        display_name = match.group(1).strip()
        email_address = match.group(2).strip()

        return display_name, email_address

    return None, None


def analyze_sender(email):
    findings = []
    score = 0

    display_name, email_address = extract_sender(email)

    if email_address is None:
        findings.append("Could not identify sender address.")
        return findings, score

    if "@" not in email_address:
        findings.append("Sender email address appears malformed.")
        return findings, score

    sender_domain = email_address.split("@")[-1].lower()

    for organization, trusted_domains in TRUSTED_ORGANIZATIONS.items():

        if organization in display_name.lower():

            if sender_domain not in trusted_domains:
                findings.append(
                        "Sender claims to represent "
                        + organization.upper()
                        + ", but uses the domain "
                        + sender_domain)
                
                score += 25

    return findings, score