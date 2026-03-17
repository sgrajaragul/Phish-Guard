"""
train.py — One-time script to train the PhishGuard ML model.

Dataset: SpamAssassin Public Corpus
  Download: https://spamassassin.apache.org/old/publiccorpus/
  Extract into:
    data/easy_ham/   (legitimate emails)
    data/spam/       (spam/phishing emails)

Usage:
  python train.py
  python train.py --data-dir ./data --limit 5000
"""

import os
import sys
import argparse
import email

# Allow running from project root
sys.path.insert(0, os.path.dirname(__file__))

from app.parser import parse_email
from app.model import train


def load_emails_from_dir(directory: str, label: int, limit: int = None) -> tuple:
    """Load all .txt / no-extension email files from a directory."""
    emails = []
    labels = []

    files = [f for f in os.listdir(directory) if not f.startswith(".")]
    if limit:
        files = files[:limit]

    print(f"  Loading {len(files)} emails from {directory} (label={label})...")

    for fname in files:
        fpath = os.path.join(directory, fname)
        try:
            with open(fpath, "rb") as f:
                raw = f.read().decode("utf-8", errors="replace")
            parsed = parse_email(raw)
            emails.append(parsed)
            labels.append(label)
        except Exception as e:
            print(f"  [!] Skipping {fname}: {e}")

    return emails, labels


def generate_synthetic_data(n_phish: int = 200, n_legit: int = 200):
    """
    Generate synthetic training emails when no dataset is available.
    Includes realistic business emails that contain words like login/verify/password
    so the model learns context, not just keywords.
    """
    import random

    phish_subjects = [
        "URGENT: Verify your account immediately",
        "Action Required: Your account will be suspended",
        "Security Alert: Unusual sign-in activity detected",
        "Your PayPal account has been limited - Act Now",
        "Confirm your identity now to avoid suspension",
        "WARNING: Unauthorized access detected on your account",
        "Your Netflix subscription payment FAILED",
        "Account compromised - reset password NOW or lose access",
        "FINAL NOTICE: Account will be permanently closed",
        "Immediate action required: Verify your banking details",
    ]
    legit_subjects = [
        "Meeting notes from Tuesday",
        "Re: Project proposal feedback",
        "Your order #12345 has shipped",
        "Monthly newsletter - March 2025",
        "Invitation: Team lunch this Friday",
        "FYI: Updated office hours next week",
        "Your invoice #INV-2025-001 is ready",
        "Welcome to our developer community",
        "Your password has been successfully reset",
        "Two-factor authentication enabled on your account",
        "Your monthly bank statement is ready to view",
        "Reminder: Please update your contact information",
        "Your subscription has been renewed",
        "Login activity: New device sign-in",
        "Action required: Review your account settings",
    ]
    phish_bodies = [
        "Dear customer, your account has been compromised. Click here immediately to verify your identity: http://192.168.1.1/login.php. Enter your password and credit card number now.",
        "We detected unauthorized access. Confirm your password and credit card details immediately at http://paypal-secure.xyz/verify or your account will be closed in 24 hours.",
        "URGENT: Your account will be terminated. Login now at http://paypal.com.verify-account.xyz/secure and enter your social security number to prevent closure.",
        "Your account is at risk. Verify your banking information immediately: http://172.16.0.1/bank/verify?user=victim. Provide your account number and PIN.",
        "Click below NOW to confirm your identity or lose access forever: http://evil.tk/account/suspended. Enter credit card details to restore access.",
        "Security breach detected. Go to http://microsoft-verify.xyz/login and enter your Windows password and social security number to secure your account.",
    ]
    legit_bodies = [
        "Hi team, sharing the notes from Tuesday's call. Please review and let me know if anything is missing. Thanks!",
        "Thanks for your purchase! Your order #12345 has shipped and will arrive in 3-5 business days. Track at https://amazon.com/orders/12345",
        "Please find attached the monthly report for your review. Feel free to reach out with any questions.",
        "Hi, hoping you're doing well. Wanted to check if you're free for a quick call this week to discuss the Q2 roadmap.",
        "Your password was successfully reset. If you didn't do this, please contact support immediately at https://support.company.com",
        "We noticed a new sign-in to your account from a new device. If this was you, no action is needed. If not, visit https://mybank.com/security to secure your account.",
        "Your March statement is now available. Log in to your account at https://mybank.com/login to view your statement.",
        "As a reminder, please update your contact information in our HR portal by end of month. Visit https://hr.company.com/profile",
        "Your annual subscription has been renewed. You can manage your account and billing at https://app.company.com/account",
        "Two-factor authentication has been enabled on your account. You'll need your phone to sign in from now on.",
        "Hi, this is a reminder that your invoice is due next week. Please log in to view and pay at https://billing.company.com",
        "Your weekly digest: 3 new pull requests, 5 issues closed. View your activity at https://github.com/dashboard",
    ]

    emails = []
    labels = []

    for _ in range(n_phish):
        # Add clear phishing signals: suspicious domains, IP URLs, mismatched reply-to
        domains = ["paypal-verify.xyz", "amazon-secure.tk", "microsoft-alert.ml",
                   "bank-update.cf", "netflix-billing.xyz", "apple-id-verify.top"]
        evil_domains = ["attacker@evil.tk", "hacker@steal.xyz", "noreply@phish.ml"]
        emails.append(parse_email(
            f"From: security@{random.choice(domains)}\n"
            f"Subject: {random.choice(phish_subjects)}\n"
            f"Reply-To: {random.choice(evil_domains)}\n\n"
            f"{random.choice(phish_bodies)}"
        ))
        labels.append(1)

    for _ in range(n_legit):
        # Use realistic corporate/service domains, no reply-to mismatch
        domains = ["company.com", "github.com", "amazon.com", "mybank.com",
                   "hr.company.com", "billing.company.com", "newsletter@medium.com"]
        emails.append(parse_email(
            f"From: noreply@{random.choice(domains)}\n"
            f"Subject: {random.choice(legit_subjects)}\n\n"
            f"{random.choice(legit_bodies)}"
        ))
        labels.append(0)

    return emails, labels


def main():
    parser = argparse.ArgumentParser(description="Train PhishGuard ML model")
    parser.add_argument("--data-dir",  default="./data",  help="Dataset root directory")
    parser.add_argument("--ham-dir",   default="easy_ham", help="Subdirectory for legit emails")
    parser.add_argument("--spam-dir",  default="spam",    help="Subdirectory for phishing/spam emails")
    parser.add_argument("--limit",     type=int, default=None, help="Max emails per class")
    parser.add_argument("--synthetic", action="store_true", help="Use synthetic data (demo mode)")
    args = parser.parse_args()

    print("=" * 55)
    print("  PhishGuard — Model Training")
    print("=" * 55)

    if args.synthetic:
        print("[*] Using synthetic training data (demo mode)")
        print("[!] For production accuracy, use the SpamAssassin corpus.")
        emails, labels = generate_synthetic_data(n_phish=300, n_legit=300)
    else:
        ham_path  = os.path.join(args.data_dir, args.ham_dir)
        spam_path = os.path.join(args.data_dir, args.spam_dir)

        if not os.path.isdir(ham_path) or not os.path.isdir(spam_path):
            print(f"[!] Dataset directories not found:")
            print(f"    Expected: {ham_path}")
            print(f"    Expected: {spam_path}")
            print()
            print("Options:")
            print("  1. Download SpamAssassin corpus from:")
            print("     https://spamassassin.apache.org/old/publiccorpus/")
            print("     Extract easy_ham/ and spam/ into ./data/")
            print()
            print("  2. Run with --synthetic flag for a demo model:")
            print("     python train.py --synthetic")
            sys.exit(1)

        legit_emails,  legit_labels  = load_emails_from_dir(ham_path,  label=0, limit=args.limit)
        phish_emails,  phish_labels  = load_emails_from_dir(spam_path, label=1, limit=args.limit)

        emails = legit_emails + phish_emails
        labels = legit_labels + phish_labels

    print(f"\n[*] Total emails: {len(emails)} ({sum(labels)} phishing, {len(labels)-sum(labels)} legit)")

    bundle = train(emails, labels, save=True)

    print("\n✅ Training complete!")
    print("   Run `python app.py` to start the web server.")


if __name__ == "__main__":
    main()
