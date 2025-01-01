import requests  # Send Requests To API Have on VT
import whois
import tkinter as tk
from tkinter import messagebox, Text

# Length Analysis
def check_length(domain):
    length = len(domain)
    if length > 20:  # Suspicious
        return f"The domain '{domain}' may be malicious (length > 20)."
    else:
        return f"The domain '{domain}' seems normal (length ≤ 20)."

# Check on Virus Total
def check_VT(domain, api_key):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            if data["data"]["attributes"]["last_analysis_stats"]["malicious"] > 0:
                return f"The domain '{domain}' is flagged as malicious by VirusTotal."
            else:
                return f"The domain '{domain}' is clean according to VirusTotal."
        else:
            return f"[ERROR] VirusTotal API returned status code: {response.status_code}"
    except Exception as e:
        return f"[ERROR] An error occurred: {e}"

# Check Whois
def check_WhoIs(domain):
    try:
        domain_info = whois.whois(domain)
        info = {
            "Domain Name": domain_info.domain_name,
            "Registrar": domain_info.registrar,
            "Creation Date": domain_info.creation_date,
            "Expiration Date": domain_info.expiration_date,
            "Name Servers": domain_info.name_servers,
            "Status": domain_info.status,
        }
        result = "\n".join([f"{key}: {value}" for key, value in info.items()])
        return f"[INFO] Whois Information:\n{result}"
    except Exception as e:
        return f"[ERROR] Failed to fetch Whois information: {e}"

# Check in Threat Intelligence Platform
def check_in_Threat_Intel(domain, api_key):
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
    headers = {"X-OTX-API-KEY": api_key}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return f"⚠️ The domain '{domain}' has information in AlienVault OTX."
        else:
            return f"✅ The domain '{domain}' is clean according to AlienVault OTX."
    except Exception as e:
        return f"[ERROR] An error occurred: {e}"

# Main Function for the UI
def analyze_domain():
    domain = domain_entry.get()
    if not domain:
        messagebox.showerror("Error", "Please enter a domain!")
        return

    api_key_vt = vt_api_entry.get()
    api_key_tip = tip_api_entry.get()
    
    # Results
    vt_result = check_VT(domain, api_key_vt)
    whois_result = check_WhoIs(domain)
    length_result = check_length(domain)
    tip_result = check_in_Threat_Intel(domain, api_key_tip)

    # Display results
    results_text.delete(1.0, tk.END)
    results_text.insert(tk.END, f"Domain Analysis for: {domain}\n")
    results_text.insert(tk.END, "-" * 40 + "\n")
    results_text.insert(tk.END, f"{length_result}\n")
    results_text.insert(tk.END, f"{vt_result}\n")
    results_text.insert(tk.END, f"{whois_result}\n")
    results_text.insert(tk.END, f"{tip_result}\n")

# Tkinter UI
root = tk.Tk()
root.title("Domain Threat Analysis Tool")
root.geometry("600x600")

# Domain Input
tk.Label(root, text="Enter Domain:", font=("Arial", 12)).pack(pady=5)
domain_entry = tk.Entry(root, font=("Arial", 12), width=40)
domain_entry.pack(pady=5)

# VirusTotal API Key Input
tk.Label(root, text="VirusTotal API Key:", font=("Arial", 12)).pack(pady=5)
vt_api_entry = tk.Entry(root, font=("Arial", 12), width=40)
vt_api_entry.pack(pady=5)

# AlienVault OTX API Key Input
tk.Label(root, text="AlienVault OTX API Key:", font=("Arial", 12)).pack(pady=5)
tip_api_entry = tk.Entry(root, font=("Arial", 12), width=40)
tip_api_entry.pack(pady=5)

# Analyze Button
analyze_button = tk.Button(root, text="Analyze Domain", font=("Arial", 12), command=analyze_domain)
analyze_button.pack(pady=20)

# Results Display
tk.Label(root, text="Results:", font=("Arial", 12)).pack(pady=5)
results_text = Text(root, font=("Arial", 12), width=70, height=20)
results_text.pack(pady=5)

# Run the Tkinter Main Loop
root.mainloop()
