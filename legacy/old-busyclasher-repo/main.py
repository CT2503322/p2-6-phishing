# A simple rule-based phishing detection system.
# This script analyzes an email's sender, subject, and body for common
# phishing indicators and returns a score. A higher score indicates a
# greater likelihood of being a phishing email.

import re

def check_for_phishing(sender_email, subject, body, headers=None, attachments=0):
    """
    Analyzes an email for phishing indicators based on a set of rules.

    Args:
        sender_email (str): The email address of the sender.
        subject (str): The subject line of the email.
        body (str): The main text of the email body.
        headers (dict, optional): A dictionary of email headers. Defaults to None.
        attachments (int, optional): The number of attachments. Defaults to 0.

    Returns:
        int: A phishing score. A score of 3 or more suggests a high
             likelihood of being a phishing email.
    """
    phishing_score = 0
    suspicious_words = [
        "urgent", "action required", "verify", "password", "account",
        "suspended", "unusual activity", "invoice", "payment", "security alert",
        "click here", "update", "confidential", "financial", "login"
    ]
    suspicious_sender_domains = [
        "secure-updates.co", "microsoft-support.net", "apple-id-verify.info",
        "paypal-billing.org", "googleservice.net"
    ]

    # Rule 1: Check for generic or suspicious sender domains
    # This rule looks for domains that don't match the purported sender.
    sender_domain = sender_email.split('@')[-1]
    if any(domain in sender_domain for domain in suspicious_sender_domains):
        print("  - Suspicious sender domain detected: " + sender_domain)
        phishing_score += 2

    # Rule 2: Check for a high number of suspicious keywords
    # This rule checks if keywords commonly used in phishing emails are present
    # in the subject or body.
    combined_text = (subject + " " + body).lower()
    for word in suspicious_words:
        if re.search(r'\b' + re.escape(word) + r'\b', combined_text):
            phishing_score += 1

    # Rule 3: Look for URLs that might be a link-shortening service
    # Phishing emails often use short URLs to hide the real destination.
    url_pattern = re.compile(r'bit\.ly|tinyurl\.com|goo\.gl', re.IGNORECASE)
    if url_pattern.search(body):
        print("  - Shortened URL detected.")
        phishing_score += 2

    # Rule 4: Check for a sense of urgency in the subject line
    # Phishing attackers often use urgency to get a quick response.
    if "urgent" in subject.lower() or "action required" in subject.lower():
        print("  - Urgent subject line detected.")
        phishing_score += 1

    # Rule 5: Look for direct requests for personal or financial information
    # This rule searches for explicit requests for sensitive data.
    personal_info_keywords = ["password", "credit card", "social security", "bank account", "pin"]
    if any(keyword in combined_text for keyword in personal_info_keywords):
        print("  - Request for personal info detected.")
        phishing_score += 3

    # Rule 6: Check for suspicious email headers (e.g., forged 'Reply-To')
    # Phishing emails may have inconsistencies in headers.
    if headers and 'Reply-To' in headers and headers['Reply-To'] != sender_email:
        print("  - Suspicious Reply-To header detected.")
        phishing_score += 2

    # Rule 7: Check for an unusual number of attachments
    # Phishing emails can sometimes include malicious attachments.
    if attachments > 0:
        print(f"  - Email contains {attachments} attachment(s).")
        if attachments > 2: # Heuristic: More than 2 attachments might be suspicious
             phishing_score += 2
        else:
            phishing_score += 1 # Slight increase for any attachment

    # Rule 8: Check for inconsistencies in sender name and email
    # Phishers often use a display name that doesn't match the email address.
    if headers and 'From' in headers:
        from_header = headers['From']
        # Simple check if the display name doesn't contain the email domain
        if from_header != sender_email and sender_domain not in from_header:
             print("  - Inconsistent sender name and email detected.")
             phishing_score += 1


    return phishing_score

# Main section to demonstrate the function with example emails
if __name__ == "__main__":

    # Example 1: A clear phishing email with added headers and attachment info
    phishing_email = {
        "sender": "support@secure-updates.co",
        "subject": "Action Required: Your Account Has Been Suspended",
        "body": "Dear valued customer,\n\nWe have detected unusual activity on your account. To prevent unauthorized access, you must verify your information immediately. Please click the link below to update your password and avoid account deactivation.\n\nhttps://bit.ly/update-now",
        "headers": {"Reply-To": "phishing@example.com", "From": '"Customer Support" <support@secure-updates.co>'},
        "attachments": 1
    }

    print("--- Analyzing Phishing Email ---")
    score = check_for_phishing(phishing_email["sender"], phishing_email["subject"], phishing_email["body"], phishing_email["headers"], phishing_email["attachments"])
    print(f"Final Phishing Score: {score}\n")
    if score >= 3:
        print("RESULT: This email is highly likely to be a phishing attempt.")
    else:
        print("RESULT: This email appears to be legitimate.")

    print("\n" + "="*50 + "\n")

    # Example 2: A legitimate email with added headers and attachment info
    legitimate_email = {
        "sender": "noreply@company.com",
        "subject": "Your Monthly Newsletter",
        "body": "Hi there,\n\nHere is your monthly newsletter with the latest updates from our team. We've included some tips on how to improve your workflow. Feel free to reach out if you have any questions.\n\nBest regards,\nThe Team",
        "headers": {"From": '"The Team" <noreply@company.com>'},
        "attachments": 0
    }

    print("--- Analyzing Legitimate Email ---")
    score = check_for_phishing(legitimate_email["sender"], legitimate_email["subject"], legitimate_email["body"], legitimate_email["headers"], legitimate_email["attachments"])
    print(f"Final Phishing Score: {score}\n")
    if score >= 3:
        print("RESULT: This email is highly likely to be a phishing attempt.")
    else:
        print("RESULT: This email appears to be legitimate.")

    print("\n" + "="*50 + "\n")

    # Example 3: Another potential phishing email
    another_phishing_email = {
        "sender": "admin@googleservice.net",
        "subject": "Security Alert: Unusual Sign-in Activity",
        "body": "We detected a sign-in attempt from a new device. If this was not you, please review your account activity immediately by clicking here: https://goo.gl/security-check",
        "headers": {"Reply-To": "support@legitservice.com", "From": '"Google Security" <admin@googleservice.net>'},
        "attachments": 0
    }

    print("--- Analyzing Another Potential Phishing Email ---")
    score = check_for_phishing(another_phishing_email["sender"], another_phishing_email["subject"], another_phishing_email["body"], another_phishing_email["headers"], another_phishing_email["attachments"])
    print(f"Final Phishing Score: {score}\n")
    if score >= 3:
        print("RESULT: This email is highly likely to be a phishing attempt.")
    else:
        print("RESULT: This email appears to be legitimate.")