import tkinter as tk
from tkinter import messagebox, ttk
import os
import dns.resolver
import datetime
import smtplib
from email.mime.text import MIMEText

# === Configuration ===
monitored_domains = {
    "example.com": ["96.7.128.175",
        "23.192.228.80",
        "96.7.128.198",
        "23.215.0.138",
        "23.215.0.136",
        "23.192.228.84"

    ]
}

USERS_FILE = "users.txt"
LOG_FILE = os.path.join(os.path.expanduser("~"), "dns_check.log")
EMAIL_FROM = "sgilki2111@ueab.ac.ke"
EMAIL_TO = "sgilki2111@ueab.ac.ke"
EMAIL_PASSWORD = "yrwxkgndltdxkxoz"
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
    except Exception as e:
        print(f"❌ Email failed: {e}")

def log_message(msg):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{now}] {msg}\n")

def show_popup(title, message, alert=False):
    win = tk.Tk()
    win.withdraw()
    if alert:
        messagebox.showerror(title, message)
    else:
        messagebox.showinfo(title, message)
    win.destroy()

def run_dns_check():
    for domain, expected_ips in monitored_domains.items():
        try:
            answers = dns.resolver.resolve(domain, 'A')
            resolved_ips = [r.to_text() for r in answers]
            suspicious_ips = [ip for ip in resolved_ips if ip not in expected_ips]

            if suspicious_ips:
                status = "ALERT"
                log_details = f"🚨 DNS Hijack Detected! | Suspicious IPs: {suspicious_ips} | Expected: {expected_ips}"
                log_message(f"{status} | {log_details}")
                send_email(f"DNS {status}", log_details)
                show_popup("🚨 DNS Hijack Detected!", "Suspicious DNS behavior detected. Please check the logs.", alert=True)
            else:
                status = "OK"
                log_message(f"{status} | ✅ DNS Verified")
                send_email("DNS OK", "All DNS checks passed. No hijack detected.")
                show_popup("✅ DNS Verified", "All DNS checks passed. No hijack detected.")
        except Exception as e:
            err = f"ERROR - {e}"
            log_message(err)
            send_email("DNS Check Error", str(e))
            show_popup("DNS Error", str(e), alert=True)

def show_logs():
    win = tk.Toplevel()
    win.title("DNS Log Viewer")
    win.geometry("750x400")
    center(win)
    win.configure(bg="#f5f5f5")

    tk.Label(win, text="Recent DNS Logs", font=("Arial", 12, "bold"), bg="#f5f5f5").pack(pady=10)

    columns = ("timestamp", "status", "message")
    table = ttk.Treeview(win, columns=columns, show="headings")
    table.heading("timestamp", text="Timestamp")
    table.heading("status", text="Status")
    table.heading("message", text="Message")
    table.column("timestamp", width=160)
    table.column("status", width=100)
    table.column("message", width=460)

    style = ttk.Style()
    style.theme_use("default")
    style.configure("Treeview", background="#ffffff", foreground="black", rowheight=25, fieldbackground="#ffffff")
    style.configure("Treeview.Heading", font=("Arial", 10, "bold"))

    table.tag_configure("green", foreground="green")
    table.tag_configure("red", foreground="red")

    table.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()[-30:]
            for line in lines:
                if "]" in line:
                    timestamp, rest = line.split("]", 1)
                    timestamp = timestamp.strip("[")
                    parts = rest.strip().split("|", 2)
                    status = parts[0].strip() if len(parts) > 0 else "INFO"
                    raw_msg = parts[1].strip() if len(parts) > 1 else ""
                    message = raw_msg.replace("example.com", "[domain]")
                    tag = "green" if "OK" in status or "Verified" in status else "red"
                    table.insert("", "end", values=(timestamp, status, message), tags=(tag,))
    except Exception as e:
        messagebox.showerror("Log Error", f"Failed to load logs: {e}")

def open_dashboard():
    dash = tk.Toplevel()
    dash.title("DNS Monitor Dashboard")
    dash.geometry("520x420")
    dash.configure(bg="#f0f4f8")
    center(dash)

    header = tk.Label(dash, text="🛡 DNS Monitor Dashboard", font=("Helvetica", 16, "bold"), bg="#f0f4f8", fg="#0b3d91")
    header.pack(pady=(30, 10))

    sub = tk.Label(dash, text="Monitor and secure your DNS traffic", font=("Helvetica", 11), bg="#f0f4f8", fg="#555")
    sub.pack()

    btn_frame = tk.Frame(dash, bg="#f0f4f8")
    btn_frame.pack(pady=30)

    style_btn = {
        "font": ("Arial", 12),
        "width": 25,
        "padx": 6,
        "pady": 6,
        "bd": 0,
        "relief": "ridge",
        "highlightthickness": 1,
        "highlightbackground": "#c0c0c0"
    }

    tk.Button(btn_frame, text="▶ Run DNS Check", command=run_dns_check, bg="#34a853", fg="white", **style_btn).pack(pady=10)
    tk.Button(btn_frame, text="📄 View Logs", command=show_logs, bg="#4285f4", fg="white", **style_btn).pack(pady=10)
    tk.Button(btn_frame, text="🚪 Logout", command=dash.destroy, bg="#ea4335", fg="white", **style_btn).pack(pady=10)

    tk.Label(dash, text="© 2025 Tonui  DNS Project", bg="#f0f4f8", fg="gray", font=("Arial", 9)).pack(side="bottom", pady=10)

def login():
    u = entry_user.get()
    p = entry_pass.get()
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r") as f:
            for line in f:
                user, pwd = line.strip().split(",")
                if u == user and p == pwd:
                    messagebox.showinfo("Welcome", f"Hello {u}!")
                    open_dashboard()
                    return
    messagebox.showerror("Login Failed", "Invalid username or password")

def register():
    u = entry_user.get()
    p = entry_pass.get()
    if u and p:
        with open(USERS_FILE, "a") as f:
            f.write(f"{u},{p}\n")
        messagebox.showinfo("Registered", "Account created. You can now log in.")
    else:
        messagebox.showwarning("Missing", "Please enter both username and password.")

def center(win):
    win.update_idletasks()
    w, h = win.winfo_width(), win.winfo_height()
    x = (win.winfo_screenwidth() // 2) - (w // 2)
    y = (win.winfo_screenheight() // 2) - (h // 2)
    win.geometry(f"+{x}+{y}")

# === Main GUI ===
root = tk.Tk()
root.title("DNS Monitor Login")
root.geometry("500x400")
root.configure(bg="#e6e9ef")
center(root)

card = tk.Frame(root, bg="white", bd=1, relief="flat", highlightthickness=0)
card.place(relx=0.5, rely=0.5, anchor="center", width=360, height=320)

tk.Label(card, text="Welcome to DNS Monitor", font=("Arial", 16, "bold"), bg="white", fg="#333").pack(pady=(20, 10))

tk.Label(card, text="Username", font=("Arial", 12), bg="white", anchor="w").pack(fill="x", padx=30)
entry_user = tk.Entry(card, font=("Arial", 12), bd=1, relief="solid")
entry_user.pack(padx=30, pady=(0, 10), fill="x")

tk.Label(card, text="Password", font=("Arial", 12), bg="white", anchor="w").pack(fill="x", padx=30)
entry_pass = tk.Entry(card, font=("Arial", 12), bd=1, relief="solid", show="*")
entry_pass.pack(padx=30, pady=(0, 20), fill="x")

btn_frame = tk.Frame(card, bg="white")
btn_frame.pack(pady=(0, 10))

tk.Button(btn_frame, text="Login", font=("Arial", 11), width=12, bg="#4CAF50", fg="white", command=login).pack(side="left", padx=5)
tk.Button(btn_frame, text="Register", font=("Arial", 11), width=12, bg="#2196F3", fg="white", command=register).pack(side="right", padx=5)

tk.Label(card, text="© 2025 Tonui DNS Security", font=("Arial", 8), bg="white", fg="gray").pack(side="bottom", pady=10)

root.mainloop()
