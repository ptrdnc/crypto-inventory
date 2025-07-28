# tls_db_loader.py

import csv
import sqlite3
import requests
import io

def load_ciphers_table(db_path="tls_ciphers.db"):
    """
    Downloads the IANA TLS Cipher Suite registry and loads it into an SQLite database.

    This function fetches the latest CSV file of TLS cipher suites from IANA,
    parses it, and populates a specified SQLite database with the relevant data.
    The table will be named 'tls_cipher_suites' and will be dropped if it already exists.

    Args:
        db_path (str, optional): The file path for the SQLite database.
                                 Defaults to "tls_ciphers.db".
    
    Raises:
        requests.exceptions.RequestException: If the download from IANA fails.
        sqlite3.Error: If a database-related error occurs.
    """
    # URL for the IANA TLS Cipher Suite registry CSV
    url = "https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv"

    # Step 1: Download the CSV from IANA
    print(f"📥 Downloading data from {url}...")
    response = requests.get(url)
    response.raise_for_status()  # Ensure the download succeeded
    print("✅ Download complete.")

    # Step 2: Parse CSV data from the response text
    # The csv.reader expects an iterator, which io.StringIO provides from a string
    csv_file = io.StringIO(response.text)
    csv_data = csv.reader(csv_file)
    next(csv_data)  # Skip the header row

    # Step 3: Connect to the SQLite database and set up the table
    # Using a 'with' statement ensures the connection is automatically closed
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()

        # Drop the table if it already exists to ensure a fresh start
        cursor.execute("DROP TABLE IF EXISTS tls_cipher_suites")

        # Create the table with columns for the cipher suite's value, name, and reference
        cursor.execute('''
        CREATE TABLE tls_cipher_suites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            value TEXT NOT NULL,
            name TEXT NOT NULL,
            reference TEXT
        )
        ''')

        # Step 4: Prepare data and insert rows into the database
        # We extract the relevant columns: Value (idx 0), Description (idx 1), and Reference (idx 4)
        rows_to_insert = []
        for row in csv_data:
            # Ensure the row has enough columns to avoid an IndexError
            if len(row) >= 5:
                value = row[0]
                name = row[1]
                reference = row[4]
                rows_to_insert.append((value, name, reference))

        # Use executemany for efficient bulk insertion
        cursor.executemany(
            "INSERT INTO tls_cipher_suites (value, name, reference) VALUES (?, ?, ?)",
            rows_to_insert
        )
        
        # The 'with' block automatically commits the transaction upon successful completion

    print(f"✔️ Successfully loaded {len(rows_to_insert)} records into {db_path}")

