"""
train_enhanced.py — Enhanced training with realistic phishing patterns

This version generates synthetic emails that closely match real-world phishing
campaigns, including common patterns seen in actual attacks.

Usage:
  python train_enhanced.py
"""

import os
import sys
import random

sys.path.insert(0, os.path.dirname(__file__))

from app.parser import parse_email
from app.model import train


def generate_realistic_phishing_emails(count=500):
    """Generate phishing emails based on real-world attack patterns."""
    
    emails = []
    labels = []
    
    # Real phishing domains and patterns observed in the wild
    phishing_domains = [
        "paypal-secure.xyz", "amazon-verify.tk", "microsoft-alert.ml",
        "netflix-billing.cf", "apple-id-verify.top", "banking-update.gq",
        "account-suspended.pw", "verify-identity.click", "urgent-action.link",
        "security-alert.site", "confirm-details.buzz", "update-required.work",
        "docusign-verify.xyz", "dropbox-share.tk", "linkedin-alert.ml",
    ]
    
    suspicious_ips = [
        "185.220.101.5", "45.142.212.61", "103.253.145.28", "91.219.237.244",
        "185.100.87.202", "45.137.22.15", "103.109.247.10", "192.3.165.30",
    ]
    
    # Actual phishing subject lines patterns
    phishing_subjects = [
        "URGENT: Your account will be suspended",
        "Action Required: Unusual sign-in activity detected",
        "Your payment method has failed - Update Now",
        "Security Alert: Unauthorized access detected",
        "Your account has been limited",
        "Verify your identity within 24 hours",
        "Important: Your password expires today",
        "Final Notice: Account will be permanently closed",
        "Suspicious Activity Report",
        "Your package could not be delivered",
        "Invoice Payment Required - DO NOT IGNORE",
        "Your subscription has expired",
        "Immediate action required to avoid suspension",
        "Confirm your bank details now",
        "Account Verification Needed",
        "Re: Your order #12345 has been cancelled",
        "Your file is ready to download",
        "Document pending signature",
        "Tax Refund: $2,475.00 awaiting",
        "Your Microsoft account security code",
    ]
    
    # Actual phishing body templates
    phishing_templates = [
        # Template 1: Account suspension threat
        """Dear Customer,

We have detected unusual activity on your account. Your account will be suspended in 24 hours unless you verify your identity immediately.

Click here to verify: http://{domain}/verify?id={random_id}

Please enter your full account credentials including:
- Email address
- Password
- Credit card number and CVV
- Social security number

If you do not complete verification, your account will be permanently deleted.

{company} Security Team""",
        
        # Template 2: Payment failure
        """Hello,

Your recent payment has failed. To avoid service interruption, please update your billing information immediately.

Update payment method: http://{ip}/billing/update.php

Enter your credit card details to restore service. Failure to act within 48 hours will result in account termination.

Thank you,
{company} Billing""",
        
        # Template 3: Package delivery
        """Dear Customer,

We attempted to deliver your package but nobody was home.

Track and reschedule: http://{domain}/track/{random_id}

Click the link above and enter your personal information to arrange redelivery. 

Parcel will be returned to sender in 3 days.

Delivery Services""",
        
        # Template 4: Security alert
        """SECURITY ALERT

Unauthorized access was detected from IP {suspicious_ip} in {country}.

If this wasn't you, click immediately: http://{ip}/security/verify

You must verify your identity by entering:
1. Current password
2. Date of birth  
3. Last 4 digits of SSN
4. Mother's maiden name

Account will be locked in 6 hours for your protection.

Security Team""",
        
        # Template 5: Document sharing
        """Hi,

{sender_name} has shared a document with you.

View document: http://{domain}/doc/view?{random_id}

Login required to access file. Enter your email and password.

This link expires in 24 hours.

Regards,
Document Management""",
        
        # Template 6: Prize/reward scam
        """Congratulations!

You have been selected to receive a $500 Amazon gift card!

Claim your reward: http://{domain}/claim?user={random_id}

To claim, verify your identity by providing:
- Full name
- Address  
- Credit card (for age verification only)

This offer expires tonight at midnight!

Amazon Rewards Program""",
        
        # Template 7: Tax refund
        """IRS Tax Refund Notice

You are eligible for a tax refund of $2,847.00

Process refund: http://{ip}/irs/refund.php

Enter your banking details to receive direct deposit:
- Bank account number
- Routing number
- Social security number

Claim expires in 72 hours.

Internal Revenue Service""",
        
        # Template 8: LinkedIn connection
        """Hello,

You have a new message from Sarah Johnson on LinkedIn.

Read message: http://{domain}/linkedin/messages/{random_id}

Login to view the full message.

This could be a new job opportunity!

LinkedIn Team""",
    ]
    
    companies = ["PayPal", "Amazon", "Microsoft", "Netflix", "Apple", "Bank of America", 
                 "Wells Fargo", "IRS", "FedEx", "UPS", "DocuSign", "LinkedIn"]
    
    countries = ["Russia", "China", "Nigeria", "Romania", "Ukraine", "Brazil"]
    
    sender_names = ["John Smith", "Sarah Johnson", "Michael Chen", "David Williams", 
                   "Lisa Anderson", "Security Team", "Support Team"]
    
    for _ in range(count):
        domain = random.choice(phishing_domains)
        ip = random.choice(suspicious_ips)
        subject = random.choice(phishing_subjects)
        template = random.choice(phishing_templates)
        company = random.choice(companies)
        
        # Generate random ID
        random_id = ''.join(random.choices('0123456789abcdef', k=16))
        
        # Fill in template
        body = template.format(
            domain=domain,
            ip=ip,
            random_id=random_id,
            company=company,
            suspicious_ip=random.choice(suspicious_ips),
            country=random.choice(countries),
            sender_name=random.choice(sender_names)
        )
        
        # Construct malicious email with realistic headers
        attacker_email = f"noreply@{domain}"
        reply_to = random.choice([
            f"support@{random.choice(phishing_domains)}",
            f"security{random.randint(1,999)}@{random.choice(phishing_domains)}",
            "attacker@evil.tk"
        ])
        
        raw_email = f"""Received: from mail.{domain} ([{ip}])
    by mail.google.com with ESMTP id xyz123
    for <victim@company.com>; {random.choice(['Mon', 'Tue', 'Wed', 'Thu', 'Fri'])}, {random.randint(1,28)} Jan 2024 {random.randint(0,23):02d}:{random.randint(0,59):02d}:00 -0800 (PST)
X-Originating-IP: [{ip}]
From: {company} <{attacker_email}>
Reply-To: {reply_to}
To: victim@company.com
Subject: {subject}
Date: Mon, 15 Jan 2024 10:30:00 -0800

{body}
"""
        
        emails.append(parse_email(raw_email))
        labels.append(1)  # Phishing
    
    return emails, labels


def generate_realistic_legitimate_emails(count=500):
    """Generate legitimate emails with realistic business patterns."""
    
    emails = []
    labels = []
    
    # Legitimate domains
    legit_domains = [
        "company.com", "github.com", "amazon.com", "google.com",
        "microsoft.com", "linkedin.com", "slack.com", "atlassian.com",
        "salesforce.com", "hubspot.com", "mailchimp.com", "stripe.com",
        "paypal.com", "apple.com", "netflix.com", "zoom.us",
    ]
    
    legit_subjects = [
        "Meeting notes from Tuesday's call",
        "Re: Q4 project proposal feedback",
        "Your order #INV-2024-001 has shipped",
        "Weekly team update - March 2024",
        "Invitation: Team lunch this Friday at 12pm",
        "FYI: Updated office hours for next week",
        "Your monthly statement is ready",
        "Welcome to our community",
        "Action required: Please review your account settings",
        "Your subscription has been renewed",
        "Two-factor authentication enabled successfully",
        "New comment on your pull request #1234",
        "Your invoice is ready for download",
        "Reminder: Meeting in 15 minutes",
        "Re: Following up on our discussion",
        "Your password was successfully changed",
        "Login activity: New device sign-in detected",
        "Monthly newsletter - Product updates",
        "Your ticket #12345 has been resolved",
        "Feedback requested: Recent purchase",
    ]
    
    legit_templates = [
        # Template 1: Business update
        """Hi team,

Just sharing a quick update from today's meeting. Here are the key points:

1. Project deadline moved to March 30th
2. New feature requests logged in Jira
3. Code review session scheduled for Thursday

Let me know if you have any questions.

Best regards,
Sarah""",
        
        # Template 2: Order confirmation  
        """Thank you for your order!

Order #INV-2024-{random_id}
Total: ${amount}

Your items will ship within 2-3 business days. Track your package at:
https://amazon.com/orders/{random_id}

Questions? Contact our support team at support@amazon.com

The Amazon Team""",
        
        # Template 3: Password reset confirmation
        """Hello,

Your password was successfully reset on {date} at {time} from IP {ip}.

If you did not make this change, please contact our security team immediately:
https://support.{domain}/security

For your security, we recommend:
- Using a unique password
- Enabling two-factor authentication  
- Reviewing recent account activity

Best regards,
{company} Security""",
        
        # Template 4: Newsletter
        """Hi there,

Here's what's new this month:

🚀 New features launched
📊 Product updates and improvements  
📝 Helpful resources and guides

Read the full update on our blog:
https://{domain}/blog/march-2024-update

You can manage your email preferences at:
https://{domain}/settings/notifications

Thanks,
The {company} Team""",
        
        # Template 5: Meeting invite
        """Hello,

You're invited to join our team meeting:

Topic: Q2 Planning Discussion
Date: Thursday, March 21, 2024
Time: 2:00 PM - 3:00 PM EST
Location: Conference Room A

Agenda:
- Review Q1 results
- Q2 goals and objectives
- Budget planning

Please confirm your attendance.

Best,
Michael""",
        
        # Template 6: Support ticket
        """Hi,

Your support ticket #SUP-{random_id} has been resolved.

Issue: Login problems
Resolution: Password reset link sent

If you have any other questions, feel free to reopen this ticket or create a new one at:
https://support.{domain}/tickets

We're here to help!

{company} Support Team""",
        
        # Template 7: Subscription renewal
        """Hello,

Your annual subscription to {company} has been renewed.

Plan: Professional
Next billing date: March 15, 2025
Amount: ${amount}

View your invoice and manage billing at:
https://{domain}/account/billing

Thank you for being a valued customer!

{company}""",
    ]
    
    companies = ["GitHub", "Amazon", "Google", "Microsoft", "LinkedIn", 
                "Slack", "Atlassian", "Salesforce", "Stripe"]
    
    for _ in range(count):
        domain = random.choice(legit_domains)
        subject = random.choice(legit_subjects)
        template = random.choice(legit_templates)
        company = companies[legit_domains.index(domain)] if domain in legit_domains[:len(companies)] else "Company"
        
        random_id = ''.join(random.choices('0123456789ABCDEF', k=12))
        amount = f"{random.randint(10, 500)}.{random.randint(0,99):02d}"
        
        # Legitimate IP from Google/AWS/Azure ranges
        legit_ips = [
            "142.250.185.5", "52.94.236.248", "13.107.21.200",
            "172.217.14.206", "34.102.136.180", "40.76.4.15"
        ]
        
        body = template.format(
            domain=domain,
            random_id=random_id,
            amount=amount,
            company=company,
            date="March 15, 2024",
            time="10:30 AM EST",
            ip=random.choice(legit_ips)
        )
        
        sender_email = f"noreply@{domain}"
        
        # Legitimate emails have matching reply-to and no IP obfuscation
        raw_email = f"""Received: from mail.{domain} (mail.{domain} [{random.choice(legit_ips)}])
    by mail.google.com with ESMTPS id abc{random.randint(100,999)}
    for <user@company.com>; {random.choice(['Mon', 'Tue', 'Wed', 'Thu', 'Fri'])}, {random.randint(1,28)} Mar 2024 {random.randint(0,23):02d}:{random.randint(0,59):02d}:00 -0800 (PST)
From: {company} <{sender_email}>
To: user@company.com
Subject: {subject}
Date: Mon, 15 Mar 2024 10:30:00 -0800

{body}
"""
        
        emails.append(parse_email(raw_email))
        labels.append(0)  # Legitimate
    
    return emails, labels


def main():
    print("=" * 70)
    print("  PhishGuard — Enhanced Model Training")
    print("  Realistic phishing patterns based on actual campaigns")
    print("=" * 70)
    print()
    
    print("[*] Generating realistic phishing emails (500)...")
    phish_emails, phish_labels = generate_realistic_phishing_emails(500)
    
    print("[*] Generating realistic legitimate emails (500)...")
    legit_emails, legit_labels = generate_realistic_legitimate_emails(500)
    
    # Combine
    all_emails = phish_emails + legit_emails
    all_labels = phish_labels + legit_labels
    
    print(f"\n[*] Total: {len(all_emails)} emails ({sum(all_labels)} phishing, {len(all_labels)-sum(all_labels)} legit)")
    print()
    
    # Train
    bundle = train(all_emails, all_labels, save=True)
    
    print("\n" + "=" * 70)
    print("✅ Training complete with realistic phishing patterns!")
    print("=" * 70)
    print("\nYour model should now accurately detect:")
    print("  ✓ Account suspension threats")
    print("  ✓ Payment failure scams")
    print("  ✓ Fake security alerts")
    print("  ✓ Credential harvesting attempts")
    print("  ✓ Package delivery scams")
    print("  ✓ Document sharing phishing")
    print("  ✓ Prize/reward scams")
    print()
    print("Run `python app.py` to test with your real phishing samples!")
    print()


if __name__ == "__main__":
    main()
