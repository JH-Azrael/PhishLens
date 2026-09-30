# Updated for Version 1.2

import re
import ipaddress
from urllib.parse import urlparse


TRUSTED_DOMAINS = {
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

def check_domain_impersonation(domain):
    findings = []
    score = 0

    for organization, trusted_domains in TRUSTED_DOMAINS.items():

        for trusted_domain in trusted_domains:

            #Trusted name appears in the hostname
            if trusted_domain in domain:

                #hostname is not actually that trusted domain
                if (
                    domain != trusted_domain
                    and not domain.endswith("." + trusted_domain)
                ):
                    findings.append(
                        f"Possible {organization.upper()} impersonation: "
                        f"{trusted_domain} appears inside the hostname "
                        f"{domain}"
                    )

                    score += 25

    return findings, score


def is_valid_ip(ip_string):
    try:
        ipaddress.ip_address(ip_string)
        return True
    except ValueError:
        return False


def extract_urls(email):
    pattern = r'https?://[^\s<>"\']+'
    return re.findall(pattern, email)


def analyze_urls(email):
    urls = extract_urls(email)

    findings = []
    score = 0

    suspicious_words = [
        "login",
        "verify",
        "secure",
        "account",
        "update",
        "password",
        "signin"
    ]

    for url in urls:
        parsed_url = urlparse(url)

        # hostname is better than netloc here because it removes ports
        domain = parsed_url.hostname

        if domain is None:
            continue

        domain = domain.lower()

        # Check for domain impersonation
        impersonation_findings, impersonation_score = check_domain_impersonation(domain)

        findings.extend(impersonation_findings)
        score += impersonation_score

        # Check if the URL directly uses an IP address
        if is_valid_ip(domain):
            findings.append(
                f"URL uses an IP address instead of a domain: {url}"
            )
            score += 25

        # Check for suspicious words
        for word in suspicious_words:
            if word in url.lower():
                findings.append(
                    f"Suspicious word '{word}' found in URL: {url}"
                )
                score += 5

        # Check for unusually long URLs
        if len(url) > 100:
            findings.append(
                f"Unusually long URL detected: {url}"
            )
            score += 10

        # Check for excessive subdomains
        if not is_valid_ip(domain) and domain.count(".") >= 3:
            findings.append(
                f"URL contains many subdomains: {domain}"
            )
            score += 10

    return findings, score