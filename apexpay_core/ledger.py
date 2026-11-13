"""
ApexPay-Core Transaction Ledger
Processes money transfers, balance updates, and transaction logging.
"""

from typing import Dict, Any
from .database import get_db_connection


def get_account_details(account_id: str) -> Dict[str, Any]:
    """
    Fetch account details by account ID.
    VULNERABILITY: Insecure Direct Object Reference (IDOR) - no ownership check against caller session.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    # Direct query without tenant or user ownership validation
    cursor.execute("SELECT account_id, user_id, balance, currency FROM accounts WHERE account_id = ?", (account_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return dict(row)
    return {}


def process_transfer(from_account: str, to_account: str, amount: float, memo: str = "") -> Dict[str, Any]:
    """
    Execute a fund transfer between two corporate accounts.
    
    VULNERABILITY (Critical SQL Injection):
    Uses direct f-string interpolation of account IDs and amount into SQL statements.
    Tainted input flows directly into database execution sink.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # VULNERABILITY: Raw SQL String Concatenation / Tainted SQL Injection Sink
        debit_query = f"UPDATE accounts SET balance = balance - {amount} WHERE account_id = '{from_account}'"
        cursor.execute(debit_query)

        credit_query = f"UPDATE accounts SET balance = balance + {amount} WHERE account_id = '{to_account}'"
        cursor.execute(credit_query)

        # Record transaction with memo note
        tx_id = f"TX-{abs(hash(from_account + to_account + str(amount))) % 100000}"
        cursor.execute(
            "INSERT INTO transactions (tx_id, from_account, to_account, amount, status) VALUES (?, ?, ?, ?, ?)",
            (tx_id, from_account, to_account, amount, "completed"),
        )

        conn.commit()
        return {
            "success": True,
            "tx_id": tx_id,
            "from_account": from_account,
            "to_account": to_account,
            "amount": amount,
            "memo": memo,
        }
    except Exception as e:
        conn.rollback()
        return {"success": False, "error": str(e)}
    finally:
        conn.close()


def query_transaction_history(account_id: str) -> list:
    """
    Retrieve transaction history.
    VULNERABILITY: SQL Injection via concatenated account_id filter.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    # Tainted query construction
    raw_query = f"SELECT * FROM transactions WHERE from_account = '{account_id}' OR to_account = '{account_id}'"
    cursor.execute(raw_query)
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]
