class Table:
    def __init__(self, columns):
        # Store a copy of the column names.
        self.columns = list(columns)
        self.rows = []  # Each row is a list of strings

    def insert_row(self, row):
        if len(row) != len(self.columns):
            print("Column count mismatch.")
            return
        # Append a copy of the row to the rows list.
        self.rows.append(list(row))

    def select_all(self):
        # Print column headers.
        print("\t".join(self.columns))
        # Print each row.
        for row in self.rows:
            print("\t".join(row))


class Database:
    def __init__(self, password):
        # For demo purposes, we store the password in plaintext.
        self.password = password
        # Dictionary to store tables by name.
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


def main():
    # Create a new Database instance with a password.
    db_password = "secret123"
    db = Database(db_password)

    # Create a "users" table with columns "id" and "name", using proper authentication.
    user_columns = ["id", "name"]
    db.create_table(db_password, "users", user_columns)

    # Retrieve the "users" table with proper authentication.
    users = db.get_table(db_password, "users")
    if users:
        # Insert a couple of rows.
        users.insert_row(["1", "Alice"])
        users.insert_row(["2", "Bob"])
        # Display all rows in the table.
        users.select_all()
    else:
        print("Table not found or authentication failed.")


if __name__ == '__main__':
    main()
