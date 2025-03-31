import sys
from flask import Flask, request, jsonify, Response

# ------------------ Database and Table Classes ------------------

class Table:
    def __init__(self, columns):
        # Store a copy of the column names.
        self.columns = list(columns)
        self.rows = []  # Each row is a list of strings
        self._cache = None  # Cache for storing the formatted table output

    def insert_row(self, row):
        if len(row) != len(self.columns):
            print("Column count mismatch.")
            return
        # Append a copy of the row to the rows list.
        self.rows.append(list(row))
        # Invalidate the cache since the table has been updated.
        self._cache = None

    def get_formatted(self):
        # Use the cached result if available.
        if self._cache is not None:
            return self._cache
        # Generate the output string.
        header = "\t".join(self.columns)
        data = "\n".join("\t".join(row) for row in self.rows)
        result = header + "\n" + data
        # Cache the result for future calls.
        self._cache = result
        return result

    def select_all(self):
        # For backward compatibility with the demo.
        result = self.get_formatted()
        print(result)

    def update_row(self, index, new_row):
        if len(new_row) != len(self.columns):
            print("Column count mismatch.")
            return
        self.rows[index] = list(new_row)
        self._cache = None

class Database:
    def __init__(self, password):
        # The global password is only used for managing generic tables.
        self.password = password
        self.tables = {}

    def authenticate(self, password):
        return self.password == password

    def create_table(self, auth_password, name, columns):
        if not self.authenticate(auth_password):
            print(f"Authentication failed. Table '{name}' was not created.")
            return
        if name in self.tables:
            print(f"Table '{name}' already exists.")
            return
        self.tables[name] = Table(columns)

    def get_table(self, auth_password, name):
        if not self.authenticate(auth_password):
            print(f"Authentication failed. Cannot retrieve table '{name}'.")
            return None
        return self.tables.get(name)

    # Public access method for tables that do not require the global password.
    def get_public_table(self, name):
        return self.tables.get(name)

# ------------------ Helper Functions for User Management ------------------

def find_user_by_id(users_table, user_id):
    for index, row in enumerate(users_table.rows):
        if row[0] == user_id:
            return index, row
    return None, None

# ------------------ Command-line Demo Function ------------------

def main():
    # For demo purposes only: use the global password to create and populate the users table.
    db_password = "secret123"
    # Create a "users" table with columns: id, name, email, password.
    db.create_table(db_password, "users", ["id", "name", "email", "password"])
    users = db.get_table(db_password, "users")
    if users:
        users.insert_row(["user1", "Alice", "alice@example.com", "password1"])
        users.insert_row(["user2", "Bob", "bob@example.com", "password2"])
        users.select_all()
    else:
        print("Table not found or authentication failed.")

# ------------------ HTTP API using Flask ------------------

app = Flask(__name__)
# Create a global Database instance (global password used only for table management).
db = Database("secret123")
# Pre-create the 'users' table for storing user info.
db.create_table("secret123", "users", ["id", "name", "email", "password"])

# Existing table endpoints (for generic table management).
@app.route('/tables', methods=['POST'])
def create_table():
    """
    Create a new table.
    Expects JSON with keys:
      - auth_password: authentication string (global, not per-user)
      - name: table name
      - columns: list of column names
    """
    data = request.get_json()
    auth_password = data.get("auth_password")
    name = data.get("name")
    columns = data.get("columns")
    if not (auth_password and name and columns):
        return jsonify({"error": "Missing required parameters"}), 400
    if name in db.tables:
        return jsonify({"error": f"Table '{name}' already exists."}), 400
    db.create_table(auth_password, name, columns)
    return jsonify({"message": f"Table '{name}' created successfully."})

@app.route('/tables/<name>/rows', methods=['POST'])
def insert_row(name):
    """
    Insert a row into an existing table.
    Expects JSON with keys:
      - auth_password: authentication string (global, not per-user)
      - row: list of values matching the table's columns
    """
    data = request.get_json()
    auth_password = data.get("auth_password")
    row = data.get("row")
    if not (auth_password and row):
        return jsonify({"error": "Missing required parameters"}), 400
    table = db.get_table(auth_password, name)
    if table is None:
        return jsonify({"error": f"Table '{name}' not found or authentication failed."}), 404
    table.insert_row(row)
    return jsonify({"message": "Row inserted successfully."})

@app.route('/tables/<name>', methods=['GET'])
def select_all(name):
    """
    Retrieve the formatted content of a table.
    Expects query parameter:
      - auth_password: authentication string (global, not per-user)
    Returns a plain text representation of the table.
    """
    auth_password = request.args.get("auth_password")
    if not auth_password:
        return jsonify({"error": "Missing auth_password parameter"}), 400
    table = db.get_table(auth_password, name)
    if table is None:
        return jsonify({"error": f"Table '{name}' not found or authentication failed."}), 404
    result = table.get_formatted()
    return Response(result, mimetype='text/plain')

# ------------------ User Authentication Endpoints ------------------

@app.route('/auth/register', methods=['POST'])
def register():
    """
    Register a new user with a chosen password.
    Expects JSON with keys: id, name, email, password.
    """
    data = request.get_json()
    user_id = data.get("id")
    name = data.get("name")
    email = data.get("email")
    password = data.get("password")
    if not (user_id and name and email and password):
        return jsonify({"error": "Missing required parameters"}), 400

    users_table = db.get_public_table("users")
    if users_table is None:
        return jsonify({"error": "Users table not found."}), 500

    idx, existing_user = find_user_by_id(users_table, user_id)
    if existing_user:
        return jsonify({"error": "User already exists."}), 400

    users_table.insert_row([user_id, name, email, password])
    return jsonify({"message": "User registered successfully."}), 201

@app.route('/auth/login', methods=['POST'])
def login():
    """
    Login using user id and password.
    Expects JSON with keys: id, password.
    """
    data = request.get_json()
    user_id = data.get("id")
    password = data.get("password")
    if not (user_id and password):
        return jsonify({"error": "Missing required parameters"}), 400

    users_table = db.get_public_table("users")
    if users_table is None:
        return jsonify({"error": "Users table not found."}), 500

    idx, user = find_user_by_id(users_table, user_id)
    if user is None or user[3] != password:
        return jsonify({"error": "Invalid user id or password."}), 401

    # Return user info (excluding password) on successful login.
    user_info = {"id": user[0], "name": user[1], "email": user[2]}
    return jsonify({"message": "Login successful.", "user": user_info}), 200

@app.route('/auth/update-password', methods=['POST'])
def update_password():
    """
    Update the password for a user.
    Expects JSON with keys: id, old_password, new_password.
    """
    data = request.get_json()
    user_id = data.get("id")
    old_password = data.get("old_password")
    new_password = data.get("new_password")
    if not (user_id and old_password and new_password):
        return jsonify({"error": "Missing required parameters"}), 400

    users_table = db.get_public_table("users")
    if users_table is None:
        return jsonify({"error": "Users table not found."}), 500

    idx, user = find_user_by_id(users_table, user_id)
    if user is None:
        return jsonify({"error": "User not found."}), 404

    if user[3] != old_password:
        return jsonify({"error": "Old password does not match."}), 401

    # Update the password in the users table.
    user[3] = new_password
    users_table.update_row(idx, user)
    return jsonify({"message": "Password updated successfully."}), 200

# ------------------ Social Sign-In Endpoints ------------------

@app.route('/auth/google', methods=['POST'])
def google_signin():
    """
    Simulate Google sign in.
    Expects JSON with key:
      - token: the Google OAuth token
    In a production system, the token should be verified against Google's OAuth2 API.
    """
    data = request.get_json()
    token = data.get("token")
    if not token:
        return jsonify({"error": "Missing token parameter"}), 400

    # Dummy token validation for demonstration.
    if token != "valid_google_token":
        return jsonify({"error": "Invalid Google token"}), 401

    # Simulate extraction of user info from token.
    user_info = {"id": "google_1", "name": "Google User", "email": "user@google.com"}

    users_table = db.get_public_table("users")
    if users_table:
        idx, existing_user = find_user_by_id(users_table, user_info["id"])
        if not existing_user:
            # For social sign in, the password field is left empty.
            users_table.insert_row([user_info["id"], user_info["name"], user_info["email"], ""])

    return jsonify({"message": "Google sign in successful", "user": user_info}), 200

@app.route('/auth/apple', methods=['POST'])
def apple_signin():
    """
    Simulate Apple sign in.
    Expects JSON with key:
      - token: the Apple sign in token
    In a production system, the token should be verified with Apple's authentication service.
    """
    data = request.get_json()
    token = data.get("token")
    if not token:
        return jsonify({"error": "Missing token parameter"}), 400

    if token != "valid_apple_token":
        return jsonify({"error": "Invalid Apple token"}), 401

    user_info = {"id": "apple_1", "name": "Apple User", "email": "user@apple.com"}

    users_table = db.get_public_table("users")
    if users_table:
        idx, existing_user = find_user_by_id(users_table, user_info["id"])
        if not existing_user:
            users_table.insert_row([user_info["id"], user_info["name"], user_info["email"], ""])

    return jsonify({"message": "Apple sign in successful", "user": user_info}), 200

# New Facebook sign in endpoint
@app.route('/auth/facebook', methods=['POST'])
def facebook_signin():
    """
    Simulate Facebook sign in.
    Expects JSON with key:
      - token: the Facebook OAuth token
    In a production system, the token should be verified against Facebook's OAuth API.
    """
    data = request.get_json()
    token = data.get("token")
    if not token:
        return jsonify({"error": "Missing token parameter"}), 400

    if token != "valid_facebook_token":
        return jsonify({"error": "Invalid Facebook token"}), 401

    user_info = {"id": "facebook_1", "name": "Facebook User", "email": "user@facebook.com"}

    users_table = db.get_public_table("users")
    if users_table:
        idx, existing_user = find_user_by_id(users_table, user_info["id"])
        if not existing_user:
            users_table.insert_row([user_info["id"], user_info["name"], user_info["email"], ""])

    return jsonify({"message": "Facebook sign in successful", "user": user_info}), 200

# New Microsoft sign in endpoint
@app.route('/auth/microsoft', methods=['POST'])
def microsoft_signin():
    """
    Simulate Microsoft sign in.
    Expects JSON with key:
      - token: the Microsoft sign in token
    In a production system, the token should be verified with Microsoft's authentication service.
    """
    data = request.get_json()
    token = data.get("token")
    if not token:
        return jsonify({"error": "Missing token parameter"}), 400

    if token != "valid_microsoft_token":
        return jsonify({"error": "Invalid Microsoft token"}), 401

    user_info = {"id": "microsoft_1", "name": "Microsoft User", "email": "user@microsoft.com"}

    users_table = db.get_public_table("users")
    if users_table:
        idx, existing_user = find_user_by_id(users_table, user_info["id"])
        if not existing_user:
            users_table.insert_row([user_info["id"], user_info["name"], user_info["email"], ""])

    return jsonify({"message": "Microsoft sign in successful", "user": user_info}), 200

# ------------------ Entry Point ------------------

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'http':
        # Run the Flask server on all interfaces at port 8080.
        app.run(host='0.0.0.0', port=8080)
    else:
        # Run the command-line demo.
        main()
