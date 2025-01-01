import requests  # Send Requests To API Have on VT
from requests.auth import HTTPBasicAuth
import whois
import socket

# Length Analysis 
def check_length(domain):
    length = len(domain)
    if length > 20: # Suspisious 
        print(f"May be{domain} Is Malicious ")
    else:
        print(f"Domain {domain}is Normal ")
#______________________________________________

# check on Virus Total
def check_VT(domain, api):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    api = "0b76e567d1feecce155c51f40e155bff40e3baca284c3a6f6a98fb46e0f808c2"
    headers = {"x-api": api}  # Data We need it to Can Send an Req (api)
    try:
       response = requests.get(url, headers=headers)
       if response.status_code == 200:
        data = response.json()
        if data["data"]["attributes"]["last_analysis_stats"]["malicious"] > 0:
            return True  # Suspisious
        else:
            print(f"[ERROR] API returned status code: {response.status_code}")
    except Exception as e:
        print(f"[ERROR] An error occurred: {e}")
        return False  # normal 
#___________________________________________________
#check whois 
def check_WhoIs(domain):
    
    domain_info = whois.whois(domain)
    return{
        "domain_name": domain_info.domain_name,
        "registrar": domain_info.registrar,
        "creation_date": domain_info.creation_date,
        "expiration_date": domain_info.expiration_date,
        "name_servers": domain_info.name_servers,
        "status": domain_info.status
    }
    
#________________________________________________________
#connect to TIP 
def check_in_Threat_Intel(domain):
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
    headers = {
        "X-OTX-API-KEY": "YOUR_ALIENVAULT_API_KEY"
    }
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        return None
#'''
# ___________________________________________
def main():
    # Virus total
    domain = "microsoft.com"  # enter domain name 
    result_For_VT = check_VT(domain,api="0b76e567d1feecce155c51f40e155bff40e3baca284c3a6f6a98fb46e0f808c2")
    if result_For_VT:
        print(f"[ALERT] The domain '{domain}' is malicious.")
    else:
        print(f"[INFO] The domain '{domain}' is clean.")
    #_____________________________________________________
    # Who is Check 
    API_KEY = "0b76e567d1feecce155c51f40e155bff40e3baca284c3a6f6a98fb46e0f808c2"
    result_whO_IS = check_WhoIs(domain)
    if result_whO_IS:
        print("[INFO] Whois Information:")
        for key, value in result_whO_IS.items():
            print(f"{key}: {value}")
    else:
        print("[INFO] Failed to fetch Whois information.")
     # أدخل الـ API Key
    #________________________________
    result_LENGTH= check_length(domain)

    print(result_LENGTH)
    #_______________________________
    result_TIP = check_in_Threat_Intel(domain)

    if result_TIP:
        print("Domain is Malicious")
        print(result_TIP) 
    else:
        print("Not Malicous")
    #________________________________
if __name__ == "__main__":
    main()