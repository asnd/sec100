import dns.resolver
import time
import requests
from dns.resolver import NXDOMAIN
import sqlite3

def check_dns_records(mnc, mcc, operator, parent_domain, subdomains, cursor):
    available_fqdns = []
    for subdomain in subdomains:
        fqdn = f"{subdomain}.mnc{mnc:03d}.mcc{mcc:03d}.{parent_domain}"
        try:
            answers = dns.resolver.resolve(fqdn, 'A')
            if answers:
                print(f"Found A record for {fqdn}")
                available_fqdns.append(fqdn)
        except NXDOMAIN:
            pass
        except Exception:
            pass

        time.sleep(0.5)  # Add a 0.5-second pause

    # Insert data into the first table
    cursor.execute("INSERT INTO operators (mnc, mcc, operator) VALUES (?, ?, ?)", (mnc, mcc, operator))

    # Insert data into the second table
    for fqdn in available_fqdns:
        cursor.execute("INSERT INTO available_fqdns (operator, fqdn) VALUES (?, ?)", (operator, fqdn))

def main():
    parent_domain = "pub.3gppnetwork.org"
    subdomains = ["ims", "epdg.epc", "bsf", "gan", "xcap.ims"]

    # Connect to SQLite database
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Create tables if they don't exist
    cursor.execute('''CREATE TABLE IF NOT EXISTS operators
                      (mnc INTEGER, mcc INTEGER, operator TEXT)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS available_fqdns
                      (operator TEXT, fqdn TEXT)''')

    # Fetch MCC-MNC pairs from JSON file
    response = requests.get('https://raw.githubusercontent.com/pbakondy/mcc-mnc-list/master/mcc-mnc-list.json')
    mcc_mnc_list = response.json()

    for item in mcc_mnc_list:
     try:
        mcc = int(item['mcc'])
        mnc = int(item['mnc'])
        operator = item['operator']
        print(item['countryName'], " ", operator)
        check_dns_records(mnc, mcc, operator, parent_domain, subdomains, cursor)
     except Exception:
       pass
    # Commit the changes and close the connection
    conn.commit()
    conn.close()

if __name__ == "__main__":
    main()
