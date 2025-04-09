import sqlite3

# Crear la base de datos y conectarse
conn = sqlite3.connect('db.db')
cursor = conn.cursor()

# Crear la tabla 'users' (sin hash, intencionalmente vulnerable)
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password TEXT NOT NULL
)
''')

# Insertar usuarios de prueba
usuarios = [
    ('admin', 'admin'),
    ('test', '1234'),
    ('usuario', 'contraseña'),
    ('victima', 'password'),
]

cursor.executemany('INSERT INTO users (username, password) VALUES (?, ?)', usuarios)

conn.commit()
conn.close()

print("✅ Base de datos 'db.db' creada con usuarios de prueba.")
