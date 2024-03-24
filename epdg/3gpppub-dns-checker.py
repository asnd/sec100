import dns.resolver
import time
import requests
from dns.resolver import NXDOMAIN

def check_dns_records(mnc, mcc, parent_domain, subdomains):
    for subdomain in subdomains:
        fqdn = f"{subdomain}.mnc{mnc:03d}.mcc{mcc:03d}.{parent_domain}"
        try:
            answers = dns.resolver.resolve(fqdn, 'A')
            if answers:
                print(f"Found A record for {fqdn}")
        except NXDOMAIN:
            pass
        except Exception:
            pass

        time.sleep(0.5)  # Add a 0.5-second pause

def main():
    parent_domain = "pub.3gppnetwork.org"
    subdomains = ["ims", "epdg.epc", "bsf", "gan", "xcap.ims"]

    # Fetch MCC-MNC pairs from JSON file
    response = requests.get('https://raw.githubusercontent.com/pbakondy/mcc-mnc-list/master/mcc-mnc-list.json')
    mcc_mnc_list = response.json()

    for item in mcc_mnc_list:
        mcc = int(item['mcc'])
        mnc = int(item['mnc'])
        print(item['countryName'], " ", item['operator'])
        check_dns_records(mnc, mcc, parent_domain, subdomains)

if __name__ == "__main__":
    main()
