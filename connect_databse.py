import sqlite3

class ConnectDatabase:
    def __init__(self):
        self.conn = None
        self.cursor = None
        self.connect_db()

    def connect_db(self):
        try:
            self.conn = sqlite3.connect("passwords.db")
            self.conn.row_factory = sqlite3.Row
            self.cursor = self.conn.cursor()
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS passwords (
                pid INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                username TEXT,
                email TEXT,
                password TEXT NOT NULL,
                category TEXT,
                last_modified TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            ''')
            self.conn.commit()
        except sqlite3.Error as e:
            print(f"Database connection error: {e}")

    def add_details(self, title, username, password, category, last_modified, email=None):
        try:
            sql = "INSERT INTO passwords (title, username, email, password, category, last_modified) VALUES (?,?,?,?,?,?)"
            self.cursor.execute(sql, (title, username, email, password, category, last_modified))
            self.conn.commit()
        except sqlite3.Error as e:
            self.conn.rollback()
            print(f"Error adding details: {e}")
            raise  # Re-raise so main.py can catch and show error to user

    def update_details(self, title, username, password, category, last_modified, pid, email=None):
        try:
            sql = "UPDATE passwords SET title = ?, username = ?, email = ?, password = ?, category = ?, last_modified = ? WHERE pid = ?"
            self.cursor.execute(sql, (title, username, email, password, category, last_modified, pid))
            self.conn.commit()
        except sqlite3.Error as e:
            self.conn.rollback()
            print(f"Error updating details: {e}")
            raise  # Re-raise so main.py can catch and show error to user

    def delete_details(self,pid):
        try:
            sql = "DELETE FROM passwords WHERE pid = ?"
            self.cursor.execute(sql,(pid,))
            self.conn.commit()
        except sqlite3.Error as e:
            self.conn.rollback()
            print(f"Error deleting details: {e}")

    def search_passwords(self, search_term):
        """Search across title, username, and email."""
        try:
            sql = """
                SELECT * FROM passwords
                WHERE title LIKE ?
                   OR COALESCE(username, '') LIKE ?
                   OR COALESCE(email, '') LIKE ?
            """
            pattern = f"%{search_term}%"
            self.cursor.execute(sql, (pattern, pattern, pattern))
            return self.cursor.fetchall()
        except sqlite3.Error as e:
            print(f"Error searching passwords: {e}")
            return []

if __name__ == "__main__":
    db = ConnectDatabase()

