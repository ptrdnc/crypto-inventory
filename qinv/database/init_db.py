import sqlite3
from cipher_suites_loader import load_ciphers_table

"""
This script initializes the SQLite database for storing TLS cipher suites
and scanned services.
It creates the necessary tables if they do not exist.
"""

def load_scanned_services_table(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS scanned_services (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        IP TEXT NOT NULL,
        PORT INTEGER NOT NULL,
        BANNER TEXT,
        CIPHERS TEXT
    )
    ''')
db_path = 'example.db'
load_ciphers_table(db_path)
load_scanned_services_table(db_path)
