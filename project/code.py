import tkinter as tk
from tkinter import scrolledtext
import re
from email.parser import HeaderParser
from ipaddress import ip_address


def is_private_ip(ip):
    try:
        return ip_address(ip).is_private or ip_address(ip).is_loopback
    except ValueError:
        return False


def analyze_email_headers(raw_headers: str):
    parser = HeaderParser()
    headers = parser.parsestr(raw_headers)

    analysis = {}

    # From & To
    from_addr = headers.get("From")
    analysis["From"] = from_addr
    analysis["To"] = headers.get("To")
    analysis["Subject"] = headers.get("Subject")
    analysis["Date"] = headers.get("Date")

    # Message ID
    analysis["Message-ID"] = headers.get("Message-ID")

    # SPF / DKIM / DMARC results
    spf = headers.get("Received-SPF")
    auth_res = headers.get("Authentication-Results")
    analysis["SPF"] = spf
    analysis["Authentication-Results"] = auth_res

    # Suspicious flags
    suspicious = []

    spf_pass = False
    dkim_pass = False
    dmarc_pass = False

    if spf and "pass" in spf.lower():
        spf_pass = True
    else:
        suspicious.append("⚠ SPF check missing/failed")

    if auth_res:
        if "dkim=pass" in auth_res.lower():
            dkim_pass = True
        if "dmarc=pass" in auth_res.lower():
            dmarc_pass = True
        if "dkim=fail" in auth_res.lower():
            suspicious.append("⚠ DKIM failed")
        if "dmarc=fail" in auth_res.lower():
            suspicious.append("⚠ DMARC failed")

    # Received headers (all hops)
    received_headers = headers.get_all("Received")
    hops_info = []
    sender_domain = None
    if from_addr:
        match = re.search(r"@([^\s>]+)", from_addr)
        if match:
            sender_domain = match.group(1)

    public_ip_seen = False  # Track if a public IP has appeared yet

    if received_headers:
        for i, hop in enumerate(received_headers):
            hop_info = {}
            # Extract IP
            ip_match = re.search(r"\[?(\d{1,3}(?:\.\d{1,3}){3})\]?", hop)
            if ip_match:
                ip = ip_match.group(1)
                hop_info["IP"] = ip

                if is_private_ip(ip):
                    if not public_ip_seen:
                        suspicious.append(f"⚠ Private/loopback IP detected *before* any public IP: {ip}")
                    # If private IP after public IP, no warning
                else:
                    public_ip_seen = True

            # Extract domain
            domain_match = re.search(r"from\s+([^\s]+)", hop)
            if domain_match:
                hop_info["Domain"] = domain_match.group(1)

                # Only check domain mismatch if SPF/DKIM/DMARC all failed
                if i == 0 and sender_domain and not (spf_pass or dkim_pass or dmarc_pass):
                    if sender_domain not in hop_info["Domain"]:
                        suspicious.append(
                            f"⚠ Domain mismatch: From={sender_domain}, Received={hop_info['Domain']}"
                        )

            hop_info["Raw"] = hop
            hops_info.append(hop_info)

    # If 3 or more suspicious flags, add possible spoofing warning
    if len(suspicious) >= 3:
        suspicious.append("⚠ Possible spoofing detected (3 or more suspicious indicators)")

    analysis["Received-Hops"] = hops_info
    analysis["Suspicious"] = suspicious if suspicious else ["✅ No obvious red flags detected"]

    return analysis


def run_analysis():
    raw_headers = input_text.get("1.0", tk.END).strip()
    if not raw_headers:
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, "⚠ Please paste email headers above.")
        return

    result = analyze_email_headers(raw_headers)

    output_text.delete("1.0", tk.END)
    for key, value in result.items():
        if isinstance(value, list):
            output_text.insert(tk.END, f"{key}:\n")
            for item in value:
                if isinstance(item, dict):  # for hops
                    output_text.insert(tk.END, f"  - IP: {item.get('IP')} | Domain: {item.get('Domain')}\n")
                else:  # for suspicious flags
                    color = "red" if "⚠" in item else "green"
                    output_text.insert(tk.END, f"  - {item}\n", color)
        else:
            output_text.insert(tk.END, f"{key}: {value}\n")

    # Apply color tags
    output_text.tag_config("red", foreground="red")
    output_text.tag_config("green", foreground="green")


def clear_text():
    input_text.delete("1.0", tk.END)
    output_text.delete("1.0", tk.END)


# Tkinter GUI
root = tk.Tk()
root.title("Email Header Analyzer (Smart Spoof Detection)")
root.geometry("900x650")

# Input box
tk.Label(root, text="Paste Email Headers Below:", font=("Arial", 12, "bold")).pack()
input_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=110, height=15)
input_text.pack(padx=10, pady=5)

# Buttons frame
button_frame = tk.Frame(root)
button_frame.pack(pady=5)

# Analyze button
analyze_btn = tk.Button(button_frame, text="Analyze Headers", command=run_analysis,
                        bg="blue", fg="white", font=("Arial", 11, "bold"))
analyze_btn.grid(row=0, column=0, padx=5)

# Clear button
clear_btn = tk.Button(button_frame, text="Clear", command=clear_text,
                      bg="gray", fg="white", font=("Arial", 11, "bold"))
clear_btn.grid(row=0, column=1, padx=5)

# Output box
tk.Label(root, text="Analysis Output:", font=("Arial", 12, "bold")).pack()
output_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=110, height=18)
output_text.pack(padx=10, pady=5)

root.mainloop()
