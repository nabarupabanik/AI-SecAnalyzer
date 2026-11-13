"""
ApexPay-Core: Enterprise Payment Processing Microservice
Main Flask application routing and entry points.
"""

from flask import Flask, request, jsonify, render_template_string
from .database import init_db
from .auth import authenticate_user, generate_auth_token, verify_auth_token, check_is_admin
from .ledger import process_transfer, get_account_details, query_transaction_history
from .admin import run_network_diagnostic, trigger_database_backup, read_system_audit_log

app = Flask(__name__)
# Initialize database tables on startup
init_db()


@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "service": "ApexPay Financial Transaction Gateway",
        "version": "3.4.1",
        "status": "operational",
        "endpoints": [
            "/api/auth/login",
            "/api/accounts/<account_id>",
            "/api/payments/transfer",
            "/api/statements/html",
            "/api/admin/ping",
            "/api/admin/logs"
        ]
    })


@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    user = authenticate_user(username, password)
    if not user:
        return jsonify({"error": "Invalid corporate credentials"}), 401

    token = generate_auth_token(user)
    return jsonify({
        "status": "authenticated",
        "token": token,
        "user": user
    })


@app.route("/api/accounts/<account_id>", methods=["GET"])
def account_info(account_id: str):
    """
    VULNERABILITY: Insecure Direct Object Reference (IDOR).
    Does not verify if the requesting user owns account_id.
    """
    account = get_account_details(account_id)
    if not account:
        return jsonify({"error": "Account not found"}), 404
    return jsonify({"account": account})


@app.route("/api/payments/transfer", methods=["POST"])
def transfer_funds():
    """
    Transfer funds between accounts.
    Tainted JSON values flow directly into ledger.process_transfer() SQL Injection sink.
    """
    data = request.get_json(silent=True) or {}
    from_acc = str(data.get("from_account", ""))
    to_acc = str(data.get("to_account", ""))
    try:
        amount = float(data.get("amount", 0.0))
    except (ValueError, TypeError):
        amount = 0.0
    memo = str(data.get("memo", ""))

    if not from_acc or not to_acc or amount <= 0:
        return jsonify({"error": "Missing transfer parameters"}), 400

    result = process_transfer(from_acc, to_acc, amount, memo=memo)
    if not result.get("success"):
        return jsonify({"error": result.get("error", "Transfer failed")}), 500
    return jsonify({"transfer": result})


@app.route("/api/statements/html", methods=["GET"])
def generate_statement_html():
    """
    VULNERABILITY: Cross-Site Scripting (XSS).
    Directly concatenates user-supplied 'account_id' parameter into raw HTML response
    without HTML encoding.
    """
    account_id = request.args.get("account_id", "")
    statement_title = request.args.get("title", f"Account Statement: {account_id}")

    # Vulnerable format string returned directly to client
    html_template = f"""
    <!DOCTYPE html>
    <html>
    <head><title>{statement_title}</title></head>
    <body>
        <h1>ApexPay Monthly Statement</h1>
        <h3>Account ID: {account_id}</h3>
        <p>Generated for authorized corporate holder.</p>
    </body>
    </html>
    """
    return html_template, 200, {"Content-Type": "text/html"}


@app.route("/api/admin/ping", methods=["POST"])
def admin_ping():
    """
    VULNERABILITY: Exploit Chain Target - OS Command Injection.
    Requires admin privileges, but can be reached if role tampering / broken access control succeeds.
    """
    token = request.headers.get("Authorization", "").replace("Bearer ", "").strip()
    claims = verify_auth_token(token)

    if not check_is_admin(claims):
        return jsonify({"error": "Unauthorized: Administrator privileges required"}), 403

    data = request.get_json(silent=True) or {}
    host = data.get("host", "127.0.0.1")

    # Tainted host flows directly into subprocess.run with shell=True
    diagnostic_result = run_network_diagnostic(host)
    return jsonify({"result": diagnostic_result})


@app.route("/api/admin/logs", methods=["GET"])
def admin_view_logs():
    """
    VULNERABILITY: Path Traversal / Arbitrary File Read.
    """
    token = request.headers.get("Authorization", "").replace("Bearer ", "").strip()
    claims = verify_auth_token(token)

    if not check_is_admin(claims):
        return jsonify({"error": "Unauthorized: Administrator privileges required"}), 403

    filename = request.args.get("file", "system.log")
    try:
        content = read_system_audit_log(filename)
        return jsonify({"filename": filename, "content": content})
    except Exception as e:
        return jsonify({"error": f"Failed to read log: {str(e)}"}), 500


if __name__ == "__main__":
    app.run(port=8080, debug=True)
