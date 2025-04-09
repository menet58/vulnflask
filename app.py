from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory
import sqlite3
import os
from werkzeug.utils import secure_filename
import config

# =======================
# Configuración de la app
# =======================

app = Flask(__name__)
app.secret_key = config.SECRET_KEY
app.config['UPLOAD_FOLDER'] = config.UPLOAD_FOLDER
app.config['SESSION_COOKIE_HTTPONLY'] = config.SESSION_COOKIE_HTTPONLY
app.config['SESSION_COOKIE_SECURE'] = config.SESSION_COOKIE_SECURE

# =======================
# Comentarios almacenados en memoria (XSS persistente)
# =======================
comentarios = []

# =======================
# Conexión a la base de datos
# =======================
def get_db():
    conn = sqlite3.connect('db.db')
    conn.row_factory = sqlite3.Row
    return conn

# =======================
# Ruta: Página principal
# =======================
@app.route('/')
def index():
    return render_template('index.html')

# =======================
# Ruta: Login vulnerable (SQLi)
# =======================
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db()
        cursor = conn.cursor()

        # ⚠️ Vulnerabilidad: Inyección SQL por interpolación directa
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        print("[DEBUG] Consulta SQL ejecutada:", query)  # Info leak intencional
        cursor.execute(query)
        user = cursor.fetchone()

        if user:
            session['username'] = user['username']
            return redirect(url_for('dashboard'))
        else:
            error = 'Usuario o contraseña incorrectos'

    return render_template('login.html', error=error)

# =======================
# Ruta: Acceso administrativo sin control
# =======================
@app.route('/admin')
def admin():
    # ⚠️ No hay control de autenticación aquí
    info_sensible = {
        "users_total": 999,
        "admin_token": "eyJfaWQiOiJhZG1pbi1wb3dlcjEyMyIsICJyb2xlIjoiZ29kIn0=",
        "log_server": "http://192.168.1.12/logs",
        "api_key": "TEST-KEY-1234-LEAKED"
    }
    return render_template('admin.html', data=info_sensible)

# =======================
# Ruta: Simulación de ejecución remota (RCE)
# =======================
@app.route('/cmd')
def ejecutar_comando():
    comando = request.args.get('exec')
    if not comando:
        return "⚠️ Parámetro 'exec' no recibido", 400
    try:
        # ⚠️ RCE directa (muy vulnerable)
        salida = os.popen(comando).read()
        return f"<pre>{salida}</pre>"
    except Exception as e:
        return f"Error al ejecutar comando: {e}"


# =======================
# Ruta: Dashboard sin control real de sesión (inseguro)
# =======================
@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template('dashboard.html', user=session['username'])
    else:
        return redirect(url_for('login'))

# =======================
# Ruta: Subida de archivos sin validación
# =======================
@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    message = None
    if request.method == 'POST':
        if 'file' not in request.files:
            message = "No se subió ningún archivo."
        else:
            file = request.files['file']
            if file.filename == '':
                message = "Archivo sin nombre."
            else:
                # ⚠️ Vulnerabilidad: No se verifica el tipo de archivo ni extensión
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                message = f"Archivo '{filename}' subido exitosamente."

    return render_template('upload.html', message=message)

# =======================
# Ruta: Comentarios vulnerables a XSS persistente
# =======================
@app.route('/comentarios', methods=['GET', 'POST'])
def comentarios_view():
    if request.method == 'POST':
        autor = request.form['autor']
        texto = request.form['texto']
        # ⚠️ Vulnerabilidad: Guardamos y mostramos sin sanitizar
        comentarios.append({'autor': autor, 'texto': texto})
    return render_template('comentarios.html', comentarios=comentarios)

# =======================
# Ruta: Listado de usuarios (enumeración)
# =======================
@app.route('/users')
def lista_usuarios():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username FROM users")
    usuarios = cursor.fetchall()
    return render_template('users.html', usuarios=usuarios)

# =======================
# Ruta: Perfil por ID (IDOR)
# =======================
@app.route('/profile')
def perfil():
    user_id = request.args.get('id', 1)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")  # ⚠️ No hay validación
    user = cursor.fetchone()
    if user:
        return render_template('profile.html', user=user)
    return "Usuario no encontrado", 404

# =======================
# Ruta: Oculta (para fuzzing tipo ffuf)
# =======================
@app.route('/hidden')
def hidden():
    return "🎯 Ruta oculta encontrada. Estás pensando como un pentester."

# =======================
# Ruta: Flags estilo CTF
# =======================
@app.route('/flag1')
def flag1():
    return "FLAG{admin_panel_discovered}"

@app.route('/flag2')
def flag2():
    return "FLAG{rce_executed_successfully}"


# =======================
# Ruta: Exposición directa de archivos subidos
# =======================
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# =======================
# Ruta: Debug Info expuesto
# =======================
@app.route('/debug-info')
def debug_info():
    # ⚠️ Expone datos internos y del entorno (info leak)
    return {
        "SECRET_KEY": app.secret_key,
        "UPLOAD_FOLDER": app.config['UPLOAD_FOLDER'],
        "ENV": dict(os.environ),
        "COOKIES": request.cookies,
        "SESSION": dict(session),
        "DEBUG": config.DEBUG
    }


# =======================
# Iniciar servidor (modo debug activado intencionalmente)
# =======================
if __name__ == '__main__':
    app.run(debug=config.DEBUG)
