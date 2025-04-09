from flask import Flask, request, render_template, redirect, url_for, session
import sqlite3
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'superinseguro'  # 🔐 intencionalmente débil

UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Función de conexión a la base de datos
def get_db():
    conn = sqlite3.connect('db.db')
    conn.row_factory = sqlite3.Row
    return conn

# Página principal
@app.route('/')
def index():
    return render_template('index.html')

# Login vulnerable (inyección SQL)
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db()
        cursor = conn.cursor()

        # ❌ Consulta vulnerable
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        print("DEBUG QUERY:", query)  # Se deja a propósito para info leak
        cursor.execute(query)
        user = cursor.fetchone()

        if user:
            session['username'] = user['username']
            return redirect(url_for('dashboard'))
        else:
            error = 'Usuario o contraseña incorrectos'

    return render_template('login.html', error=error)

# Panel privado
@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template('dashboard.html', user=session['username'])
    else:
        return redirect(url_for('login'))

# Subida de archivos sin validación
@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    message = None
    if request.method == 'POST':
        if 'file' not in request.files:
            message = "No se subió ningún archivo."
        else:
            file = request.files['file']
            if file.filename == '':
                message = "Nombre de archivo vacío."
            else:
                # ⚠️ No se valida el tipo de archivo
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                message = f"Archivo '{filename}' subido exitosamente."

    return render_template('upload.html', message=message)

# Lanzar la app
if __name__ == '__main__':
    app.run(debug=True)
