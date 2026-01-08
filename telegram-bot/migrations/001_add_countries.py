"""
Database migration: Add countries and phone_country_codes tables.

This migration enhances the 3GPP database with country mapping capabilities
required for the Telegram bot's country search and MSISDN parsing features.
"""

import json
import sqlite3
import os
from pathlib import Path


# E.164 country calling codes mapping to ISO country codes
# Source: ITU-T E.164 standard
# This is a subset covering the most common countries
PHONE_COUNTRY_CODES = {
    # North America
    "1": [("US", "United States"), ("CA", "Canada")],
    # Europe
    "7": [("RU", "Russia"), ("KZ", "Kazakhstan")],
    "20": [("EG", "Egypt")],
    "27": [("ZA", "South Africa")],
    "30": [("GR", "Greece")],
    "31": [("NL", "Netherlands")],
    "32": [("BE", "Belgium")],
    "33": [("FR", "France")],
    "34": [("ES", "Spain")],
    "36": [("HU", "Hungary")],
    "39": [("IT", "Italy"), ("VA", "Vatican City")],
    "40": [("RO", "Romania")],
    "41": [("CH", "Switzerland")],
    "43": [("AT", "Austria")],
    "44": [("GB", "United Kingdom")],
    "45": [("DK", "Denmark")],
    "46": [("SE", "Sweden")],
    "47": [("NO", "Norway")],
    "48": [("PL", "Poland")],
    "49": [("DE", "Germany")],
    "51": [("PE", "Peru")],
    "52": [("MX", "Mexico")],
    "53": [("CU", "Cuba")],
    "54": [("AR", "Argentina")],
    "55": [("BR", "Brazil")],
    "56": [("CL", "Chile")],
    "57": [("CO", "Colombia")],
    "58": [("VE", "Venezuela")],
    "60": [("MY", "Malaysia")],
    "61": [("AU", "Australia")],
    "62": [("ID", "Indonesia")],
    "63": [("PH", "Philippines")],
    "64": [("NZ", "New Zealand")],
    "65": [("SG", "Singapore")],
    "66": [("TH", "Thailand")],
    "81": [("JP", "Japan")],
    "82": [("KR", "South Korea")],
    "84": [("VN", "Vietnam")],
    "86": [("CN", "China")],
    "90": [("TR", "Turkey")],
    "91": [("IN", "India")],
    "92": [("PK", "Pakistan")],
    "93": [("AF", "Afghanistan")],
    "94": [("LK", "Sri Lanka")],
    "95": [("MM", "Myanmar")],
    "98": [("IR", "Iran")],
    # Middle East
    "212": [("MA", "Morocco")],
    "213": [("DZ", "Algeria")],
    "216": [("TN", "Tunisia")],
    "218": [("LY", "Libya")],
    "220": [("GM", "Gambia")],
    "221": [("SN", "Senegal")],
    "222": [("MR", "Mauritania")],
    "223": [("ML", "Mali")],
    "224": [("GN", "Guinea")],
    "225": [("CI", "Ivory Coast")],
    "226": [("BF", "Burkina Faso")],
    "227": [("NE", "Niger")],
    "228": [("TG", "Togo")],
    "229": [("BJ", "Benin")],
    "230": [("MU", "Mauritius")],
    "231": [("LR", "Liberia")],
    "232": [("SL", "Sierra Leone")],
    "233": [("GH", "Ghana")],
    "234": [("NG", "Nigeria")],
    "235": [("TD", "Chad")],
    "236": [("CF", "Central African Republic")],
    "237": [("CM", "Cameroon")],
    "238": [("CV", "Cape Verde")],
    "239": [("ST", "São Tomé and Príncipe")],
    "240": [("GQ", "Equatorial Guinea")],
    "241": [("GA", "Gabon")],
    "242": [("CG", "Republic of the Congo")],
    "243": [("CD", "Democratic Republic of the Congo")],
    "244": [("AO", "Angola")],
    "245": [("GW", "Guinea-Bissau")],
    "246": [("IO", "British Indian Ocean Territory")],
    "248": [("SC", "Seychelles")],
    "249": [("SD", "Sudan")],
    "250": [("RW", "Rwanda")],
    "251": [("ET", "Ethiopia")],
    "252": [("SO", "Somalia")],
    "253": [("DJ", "Djibouti")],
    "254": [("KE", "Kenya")],
    "255": [("TZ", "Tanzania")],
    "256": [("UG", "Uganda")],
    "257": [("BI", "Burundi")],
    "258": [("MZ", "Mozambique")],
    "260": [("ZM", "Zambia")],
    "261": [("MG", "Madagascar")],
    "262": [("RE", "Réunion"), ("YT", "Mayotte")],
    "263": [("ZW", "Zimbabwe")],
    "264": [("NA", "Namibia")],
    "265": [("MW", "Malawi")],
    "266": [("LS", "Lesotho")],
    "267": [("BW", "Botswana")],
    "268": [("SZ", "Eswatini")],
    "269": [("KM", "Comoros")],
    # Additional European codes
    "350": [("GI", "Gibraltar")],
    "351": [("PT", "Portugal")],
    "352": [("LU", "Luxembourg")],
    "353": [("IE", "Ireland")],
    "354": [("IS", "Iceland")],
    "355": [("AL", "Albania")],
    "356": [("MT", "Malta")],
    "357": [("CY", "Cyprus")],
    "358": [("FI", "Finland")],
    "359": [("BG", "Bulgaria")],
    "370": [("LT", "Lithuania")],
    "371": [("LV", "Latvia")],
    "372": [("EE", "Estonia")],
    "373": [("MD", "Moldova")],
    "374": [("AM", "Armenia")],
    "375": [("BY", "Belarus")],
    "376": [("AD", "Andorra")],
    "377": [("MC", "Monaco")],
    "378": [("SM", "San Marino")],
    "380": [("UA", "Ukraine")],
    "381": [("RS", "Serbia")],
    "382": [("ME", "Montenegro")],
    "383": [("XK", "Kosovo")],
    "385": [("HR", "Croatia")],
    "386": [("SI", "Slovenia")],
    "387": [("BA", "Bosnia and Herzegovina")],
    "389": [("MK", "North Macedonia")],
    "420": [("CZ", "Czech Republic")],
    "421": [("SK", "Slovakia")],
    "423": [("LI", "Liechtenstein")],
    # Asia-Pacific additional
    "673": [("BN", "Brunei")],
    "674": [("NR", "Nauru")],
    "675": [("PG", "Papua New Guinea")],
    "676": [("TO", "Tonga")],
    "677": [("SB", "Solomon Islands")],
    "678": [("VU", "Vanuatu")],
    "679": [("FJ", "Fiji")],
    "680": [("PW", "Palau")],
    "681": [("WF", "Wallis and Futuna")],
    "682": [("CK", "Cook Islands")],
    "683": [("NU", "Niue")],
    "685": [("WS", "Samoa")],
    "686": [("KI", "Kiribati")],
    "687": [("NC", "New Caledonia")],
    "688": [("TV", "Tuvalu")],
    "689": [("PF", "French Polynesia")],
    "690": [("TK", "Tokelau")],
    "691": [("FM", "Micronesia")],
    "692": [("MH", "Marshall Islands")],
    # Middle East additional
    "850": [("KP", "North Korea")],
    "852": [("HK", "Hong Kong")],
    "853": [("MO", "Macau")],
    "855": [("KH", "Cambodia")],
    "856": [("LA", "Laos")],
    "870": [("PN", "Pitcairn Islands")],
    "880": [("BD", "Bangladesh")],
    "886": [("TW", "Taiwan")],
    "960": [("MV", "Maldives")],
    "961": [("LB", "Lebanon")],
    "962": [("JO", "Jordan")],
    "963": [("SY", "Syria")],
    "964": [("IQ", "Iraq")],
    "965": [("KW", "Kuwait")],
    "966": [("SA", "Saudi Arabia")],
    "967": [("YE", "Yemen")],
    "968": [("OM", "Oman")],
    "970": [("PS", "Palestine")],
    "971": [("AE", "United Arab Emirates")],
    "972": [("IL", "Israel")],
    "973": [("BH", "Bahrain")],
    "974": [("QA", "Qatar")],
    "975": [("BT", "Bhutan")],
    "976": [("MN", "Mongolia")],
    "977": [("NP", "Nepal")],
    "992": [("TJ", "Tajikistan")],
    "993": [("TM", "Turkmenistan")],
    "994": [("AZ", "Azerbaijan")],
    "995": [("GE", "Georgia")],
    "996": [("KG", "Kyrgyzstan")],
    "998": [("UZ", "Uzbekistan")],
}


def create_tables(cursor):
    """Create new tables and indexes."""
    print("Creating countries table...")
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS countries (
            country_name TEXT NOT NULL,
            country_code TEXT NOT NULL,
            mcc TEXT NOT NULL,
            UNIQUE(country_name, mcc)
        )
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_countries_name ON countries(country_name)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_countries_mcc ON countries(mcc)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_countries_code ON countries(country_code)")

    print("Creating phone_country_codes table...")
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS phone_country_codes (
            phone_code TEXT NOT NULL,
            country_code TEXT NOT NULL,
            country_name TEXT NOT NULL,
            UNIQUE(phone_code, country_code)
        )
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_phone_codes ON phone_country_codes(phone_code)")

    print("Creating query_log table...")
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS query_log (
            telegram_user_id INTEGER NOT NULL,
            query_type TEXT NOT NULL,
            query_value TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            result_count INTEGER
        )
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_query_log_user ON query_log(telegram_user_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_query_log_timestamp ON query_log(timestamp)")

    print("Creating indexes on existing tables...")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_operators_mcc ON operators(mcc)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_operators_mnc ON operators(mnc)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_operators_operator ON operators(operator)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_operators_mcc_mnc ON operators(mcc, mnc)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_fqdns_operator ON available_fqdns(operator)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_fqdns_fqdn ON available_fqdns(fqdn)")


def populate_countries(cursor, mcc_mnc_data):
    """Populate countries table from MCC-MNC JSON data."""
    print("Populating countries table...")

    # Extract unique (country_name, country_code, mcc) tuples
    country_mcc_map = {}
    for entry in mcc_mnc_data:
        # Handle None values gracefully
        country_name = entry.get("countryName", "") or ""
        country_code = entry.get("countryCode", "") or ""
        mcc = entry.get("mcc", "") or ""

        # Strip only if we have strings
        country_name = country_name.strip() if isinstance(country_name, str) else ""
        country_code = country_code.strip() if isinstance(country_code, str) else ""
        mcc = mcc.strip() if isinstance(mcc, str) else ""

        if country_name and country_code and mcc:
            key = (country_name, country_code, mcc)
            country_mcc_map[key] = True

    # Insert into database
    inserted = 0
    for (country_name, country_code, mcc) in sorted(country_mcc_map.keys()):
        try:
            cursor.execute(
                "INSERT OR IGNORE INTO countries (country_name, country_code, mcc) VALUES (?, ?, ?)",
                (country_name, country_code, mcc)
            )
            if cursor.rowcount > 0:
                inserted += 1
        except sqlite3.IntegrityError:
            # Already exists, skip
            pass

    print(f"Inserted {inserted} unique country-MCC mappings")


def populate_phone_codes(cursor):
    """Populate phone_country_codes table from hardcoded E.164 mappings."""
    print("Populating phone_country_codes table...")

    inserted = 0
    for phone_code, countries in PHONE_COUNTRY_CODES.items():
        for country_code, country_name in countries:
            try:
                cursor.execute(
                    "INSERT OR IGNORE INTO phone_country_codes (phone_code, country_code, country_name) VALUES (?, ?, ?)",
                    (phone_code, country_code, country_name)
                )
                if cursor.rowcount > 0:
                    inserted += 1
            except sqlite3.IntegrityError:
                pass

    print(f"Inserted {inserted} phone country code mappings")


def run_migration(db_path, mcc_mnc_json_path):
    """Execute the migration."""
    print(f"Starting migration on database: {db_path}")
    print(f"Using MCC-MNC data from: {mcc_mnc_json_path}")

    # Load MCC-MNC JSON data
    if not os.path.exists(mcc_mnc_json_path):
        print(f"ERROR: MCC-MNC JSON file not found: {mcc_mnc_json_path}")
        return False

    print("Loading MCC-MNC JSON data...")
    with open(mcc_mnc_json_path, 'r', encoding='utf-8') as f:
        mcc_mnc_data = json.load(f)
    print(f"Loaded {len(mcc_mnc_data)} entries from MCC-MNC list")

    # Connect to database
    if not os.path.exists(db_path):
        print(f"ERROR: Database not found: {db_path}")
        return False

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        # Run migration steps
        create_tables(cursor)
        populate_countries(cursor, mcc_mnc_data)
        populate_phone_codes(cursor)

        # Commit changes
        conn.commit()
        print("\nMigration completed successfully!")

        # Print statistics
        cursor.execute("SELECT COUNT(*) FROM countries")
        country_count = cursor.fetchone()[0]
        print(f"\nStatistics:")
        print(f"  - Countries table: {country_count} entries")

        cursor.execute("SELECT COUNT(*) FROM phone_country_codes")
        phone_code_count = cursor.fetchone()[0]
        print(f"  - Phone country codes table: {phone_code_count} entries")

        cursor.execute("SELECT COUNT(DISTINCT country_name) FROM countries")
        unique_countries = cursor.fetchone()[0]
        print(f"  - Unique countries: {unique_countries}")

        return True

    except Exception as e:
        print(f"\nERROR during migration: {e}")
        conn.rollback()
        return False
    finally:
        conn.close()


if __name__ == "__main__":
    # Default paths (relative to this script's location)
    script_dir = Path(__file__).parent.parent.parent
    default_db_path = script_dir / "go-3gpp-scanner" / "bin" / "database.db"
    default_json_path = script_dir / "epdg" / "mcc-mnc-list.json"

    import sys

    db_path = sys.argv[1] if len(sys.argv) > 1 else str(default_db_path)
    json_path = sys.argv[2] if len(sys.argv) > 2 else str(default_json_path)

    success = run_migration(db_path, json_path)
    sys.exit(0 if success else 1)
