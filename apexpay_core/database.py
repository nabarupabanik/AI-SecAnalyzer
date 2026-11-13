"""
ApexPay-Core Database Module
Simulates an enterprise financial database with user accounts and transactions.
"""

import sqlite3
import os
from pathlib import Path

DB_PATH = Path(__file__).parent / "apexpay.db"


def get_db_connection() -> sqlite3.Connection:
    """Return a connection to the SQLite database."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Initialize schema and seed with realistic corporate payment data."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'customer',
        email TEXT NOT NULL
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS accounts (
        account_id TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        balance REAL NOT NULL DEFAULT 0.0,
        currency TEXT NOT NULL DEFAULT 'USD',
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS transactions (
        tx_id TEXT PRIMARY KEY,
        from_account TEXT NOT NULL,
        to_account TEXT NOT NULL,
        amount REAL NOT NULL,
        status TEXT NOT NULL DEFAULT 'completed',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Seed mock corporate data
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        cursor.execute("INSERT INTO users (username, password_hash, role, email) VALUES ('alice_corp', '5f4dcc3b5aa765d61d8327deb882cf99', 'customer', 'alice@corp.com')")
        cursor.execute("INSERT INTO users (username, password_hash, role, email) VALUES ('bob_vendor', '5f4dcc3b5aa765d61d8327deb882cf99', 'customer', 'bob@vendor.com')")
        cursor.execute("INSERT INTO users (username, password_hash, role, email) VALUES ('sysadmin', 'd033e22ae348aeb5660fc2140aec35850c4da997', 'admin', 'admin@apexpay.io')")

        cursor.execute("INSERT INTO accounts (account_id, user_id, balance, currency) VALUES ('ACC-1001', 1, 50000.0, 'USD')")
        cursor.execute("INSERT INTO accounts (account_id, user_id, balance, currency) VALUES ('ACC-1002', 2, 12500.0, 'USD')")
        cursor.execute("INSERT INTO accounts (account_id, user_id, balance, currency) VALUES ('ACC-ADMIN', 3, 999999.0, 'USD')")

        cursor.execute("INSERT INTO transactions (tx_id, from_account, to_account, amount) VALUES ('TX-9001', 'ACC-1001', 'ACC-1002', 1500.0)")

    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()
    print("ApexPay database initialized successfully.")
