from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory
import sqlite3
import os
from werkzeug.utils import secure_filename
import config 

# Configuración inicial
app = Flask(__name__)
app.secret_key = config.SECRET_KEY  # 🔥 Vulnerabilidad intencional

app.config['UPLOAD_FOLDER'] = config.UPLOAD_FOLDER
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False  # ⚠️ Poner en True si usás HTTPS


# Almacenamiento en memoria para comentarios (XSS)
comentarios = []

# =======================
# Función para conectar a la base de datos
# =======================
def get_db():
    conn = sqlite3.connect('db.db')
    conn.row_factory = sqlite3.Row
    return conn

# =======================
# Rutas
# =======================

@app.route('/')
def index():
    return render_template('index.html')

# 🔓 Login vulnerable a inyección SQL
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db()
        cursor = conn.cursor()

        # ⚠️ Consulta vulnerable (SQLi)
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        print("[DEBUG] SQL Query:", query)  # Info leak intencional
        cursor.execute(query)
        user = cursor.fetchone()

        if user:
            session['username'] = user['username']
            return redirect(url_for('dashboard'))
        else:
            error = 'Usuario o contraseña incorrectos'

    return render_template('login.html', error=error)

# 🧠 Panel privado (sin seguridad extra)
@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template('dashboard.html', user=session['username'])
    else:
        return redirect(url_for('login'))

# 📤 Subida de archivos sin validación
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
                # ⚠️ No se valida extensión ni tipo de archivo
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                message = f"Archivo '{filename}' subido exitosamente."

    return render_template('upload.html', message=message)

# 💬 Comentarios vulnerables a XSS persistente
@app.route('/comentarios', methods=['GET', 'POST'])
def comentarios_view():
    if request.method == 'POST':
        autor = request.form['autor']
        texto = request.form['texto']
        comentarios.append({'autor': autor, 'texto': texto})
    return render_template('comentarios.html', comentarios=comentarios)

# 📂 Permitir acceso a archivos subidos
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# =======================
# Iniciar servidor
# =======================
if __name__ == '__main__':
    app.run(debug=True)  # ⚠️ Debug activado a propósito (info leak)
