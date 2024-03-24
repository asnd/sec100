import streamlit as st
import sqlite3

# Connect to the SQLite database
conn = sqlite3.connect('database.db')
cursor = conn.cursor()

# Function to get available subdomains for a given MNC and MCC
def get_available_subdomains(mnc, mcc):
    cursor.execute('''
        SELECT fqdn 
        FROM available_fqdns
        WHERE operator IN (
            SELECT operator 
            FROM operators
            WHERE mnc = ? AND mcc = ?
        )
    ''', (mnc, mcc))
    subdomains = [row[0] for row in cursor.fetchall()]
    return subdomains

# Streamlit app
def main():
    st.title("MNC and MCC Lookup")

    # Get unique MNC and MCC values from the database
    cursor.execute("SELECT DISTINCT mnc, mcc FROM operators")
    mnc_mcc_list = cursor.fetchall()

    # Create dropdown menus for MNC and MCC selection
    mnc = st.selectbox("Select MNC", [row[0] for row in mnc_mcc_list])
    mcc = st.selectbox("Select MCC", [row[1] for row in mnc_mcc_list])

    # Get available subdomains for the selected MNC and MCC
    subdomains = get_available_subdomains(mnc, mcc)

    if subdomains:
        st.subheader("Available Subdomains")
        for subdomain in subdomains:
            st.write(subdomain)
    else:
        st.write("No available subdomains found for the selected MNC and MCC.")

if __name__ == '__main__':
    main()
