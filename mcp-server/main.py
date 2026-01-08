import os
import sqlite3
import logging
import socket
import concurrent.futures
from mcp.server.fastmcp import FastMCP

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mcp-3gpp")

# Initialize FastMCP
mcp = FastMCP("3gpp-scanner")

# Configuration
DB_PATH = os.environ.get("DB_PATH")

def find_database():
    if DB_PATH and os.path.exists(DB_PATH):
        return DB_PATH
    
    candidates = [
        "go-3gpp-scanner/bin/database.db",
        "database.db",
        "../database.db",
        "epdg/database.db",
        "../epdg/database.db",
        "../go-3gpp-scanner/bin/database.db"
    ]
    
    for path in candidates:
        abs_path = os.path.abspath(os.path.join(os.getcwd(), path))
        if os.path.exists(abs_path):
            return abs_path
    
    return "database.db"

DB_FILE = find_database()
logger.info(f"Using database: {DB_FILE}")

def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def resolve_fqdn(fqdn: str) -> list[str]:
    """Resolve an FQDN to a list of IP addresses."""
    try:
        # Get all info (IPv4 and IPv6)
        # AF_UNSPEC allows both, SOCK_STREAM is arbitrary here as we just want IPs
        addr_info = socket.getaddrinfo(fqdn, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
        ips = sorted(list(set(info[4][0] for info in addr_info)))
        return ips
    except Exception:
        return []

def get_operator_active_infrastructure(cursor, operator_name: str) -> str:
    """Helper to get active infrastructure details for an operator."""
    cursor.execute("SELECT mnc, mcc FROM operators WHERE operator = ?", (operator_name,))
    op_rows = cursor.fetchall()
    
    res = f"\nOperator: {operator_name}\n"
    res += "MNC/MCC Pairs:\n"
    for row in op_rows:
        res += f"- MCC: {row['mcc']}, MNC: {row['mnc']}\n"
    
    cursor.execute("SELECT fqdn FROM available_fqdns WHERE operator = ?", (operator_name,))
    fqdn_rows = cursor.fetchall()
    
    if fqdn_rows:
        active_results = []
        fqdns = [r['fqdn'] for r in fqdn_rows]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_fqdn = {executor.submit(resolve_fqdn, f): f for f in fqdns}
            for future in concurrent.futures.as_completed(future_to_fqdn):
                fqdn = future_to_fqdn[future]
                ips = future.result()
                if ips:
                    active_results.append((fqdn, ips))
        
        if active_results:
            res += "Active FQDNs & Live IPs:\n"
            for fqdn, ips in sorted(active_results):
                ip_str = ", ".join(ips)
                res += f"- {fqdn}\n  -> IPs: {ip_str}\n"
        else:
            res += "No active FQDNs found.\n"
    else:
        res += "No FQDNs found in database.\n"
    return res

@mcp.tool()
def query_mnc(mnc_code: int) -> str:
    """Query operators and their active infrastructure by MNC code."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT DISTINCT operator FROM operators WHERE mnc = ?", (mnc_code,))
        operators = cursor.fetchall()
        if not operators:
            return f"No operators found for MNC {mnc_code}"
        
        res = f"Infrastructure for MNC {mnc_code}:\n"
        for op in operators:
            res += get_operator_active_infrastructure(cursor, op['operator'])
        return res
    except Exception as e:
        return f"Error: {str(e)}"
    finally:
        conn.close()

@mcp.tool()
def query_mcc(mcc_code: int) -> str:
    """Query operators and their active infrastructure by MCC code."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT DISTINCT operator FROM operators WHERE mcc = ?", (mcc_code,))
        operators = cursor.fetchall()
        if not operators:
            return f"No operators found for MCC {mcc_code}"
        
        res = f"Infrastructure for MCC {mcc_code}:\n"
        for op in operators:
            res += get_operator_active_infrastructure(cursor, op['operator'])
        return res
    except Exception as e:
        return f"Error: {str(e)}"
    finally:
        conn.close()

@mcp.tool()
def query_operator(operator_name: str) -> str:
    """Query details and active FQDNs for a specific operator."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        # Exact match check
        cursor.execute("SELECT 1 FROM operators WHERE operator = ?", (operator_name,))
        if not cursor.fetchone():
            # Try partial match
            cursor.execute("SELECT DISTINCT operator FROM operators WHERE operator LIKE ?", (f"%{operator_name}%",))
            matches = cursor.fetchall()
            if matches:
                res = f"Operator '{operator_name}' not found. Did you mean:\n"
                for m in matches:
                    res += f"- {m['operator']}\n"
                return res
            return f"Operator '{operator_name}' not found."

        return get_operator_active_infrastructure(cursor, operator_name)
    except Exception as e:
        return f"Error: {str(e)}"
    finally:
        conn.close()

if __name__ == "__main__":
    # run() defaults to stdio if no arguments, 
    # but can be configured for SSE.
    mcp.run()
