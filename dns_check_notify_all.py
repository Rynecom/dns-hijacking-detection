import dns.resolver
import datetime
import smtplib
from email.mime.text import MIMEText

# === Configuration ===
monitored_domains = {
    "example.com": ["1.1.1.1"
   
    ]
}
log_file = "dns_check.log"
# Email Settings
EMAIL_FROM = "sgilki2111@ueab.ac.ke"
EMAIL_TO = "sgilki2111@ueab.ac.ke"
EMAIL_PASSWORD = "pxzrreogxwokxnyw"  # Use your Gmail App Password here
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

def send_email(subject, body):
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = EMAIL_FROM
    msg["To"] = EMAIL_TO

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_FROM, EMAIL_PASSWORD)
            server.send_message(msg)
        print("Email sent.")
    except Exception as e:
        print(f"Email failed: {e}")

def check_dns(domain, expected_ips):
    try:
        answers = dns.resolver.resolve(domain, 'A')
        resolved_ips = [r.to_text() for r in answers]
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if not any(ip in resolved_ips for ip in expected_ips):
            status = "ALERT"
            log = f"[{now}] {status}: {domain} resolved to {resolved_ips}, expected one of {expected_ips}"
        else:
            status = "OK"
            log = f"[{now}] {status}: {domain} resolved to {resolved_ips}"

        print(log)
        with open(log_file, "a") as f:
            f.write(log + "\n")

        send_email(subject=f"DNS {status} for {domain}", body=log)

    except Exception as e:
        error_log = f"[{datetime.datetime.now()}] ERROR: {e}"
        print(error_log)
        with open(log_file, "a") as f:
            f.write(error_log + "\n")
        send_email(subject="DNS Check Error", body=error_log)

# === Run Check ===
for domain, ip_list in monitored_domains.items():
    check_dns(domain, ip_list)
