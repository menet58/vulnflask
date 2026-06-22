import sqlite3
from pathlib import Path


DB_PATH = Path(__file__).resolve().parent / "db.db"


conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

cursor.execute("DROP TABLE IF EXISTS users")
cursor.execute("DROP TABLE IF EXISTS comments")

cursor.execute(
    """
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password TEXT NOT NULL
    )
    """
)

cursor.execute(
    """
    CREATE TABLE comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        author TEXT NOT NULL,
        body TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """
)

users = [
    ("admin", "admin"),
    ("test", "1234"),
    ("usuario", "contrasena"),
    ("victima", "password"),
]

comments = [
    ("admin", "Bienvenido al laboratorio XSS."),
    ("tester", "<strong>Este HTML se renderiza sin escape.</strong>"),
]

cursor.executemany("INSERT INTO users (username, password) VALUES (?, ?)", users)
cursor.executemany("INSERT INTO comments (author, body) VALUES (?, ?)", comments)

conn.commit()
conn.close()

print(f"Base de datos creada en {DB_PATH}")
