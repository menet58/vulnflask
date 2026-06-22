from pathlib import Path
import os
import sqlite3

from flask import Flask, redirect, render_template, request, send_from_directory, session, url_for
from werkzeug.utils import secure_filename

try:
    import yara
except ImportError:
    yara = None


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "db.db"
UPLOAD_FOLDER = BASE_DIR / "uploads"
RULES_FOLDER = BASE_DIR / "rules"

app = Flask(__name__)
app.secret_key = "superinseguro"  # Intencionalmente debil para el laboratorio.
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

UPLOAD_FOLDER.mkdir(exist_ok=True)
RULES_FOLDER.mkdir(exist_ok=True)


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_lab_cards():
    return [
        {
            "title": "SQL Injection",
            "risk": "Critico",
            "path": "/login",
            "description": "Login con consulta SQL construida por string interpolation.",
        },
        {
            "title": "Upload inseguro",
            "risk": "Alto",
            "path": "/upload",
            "description": "Subida de archivos sin validacion de extension, MIME ni contenido.",
        },
        {
            "title": "XSS persistente",
            "risk": "Alto",
            "path": "/comentarios",
            "description": "Comentarios guardados en base de datos y renderizados sin escape.",
        },
        {
            "title": "Admin expuesto",
            "risk": "Medio",
            "path": "/admin",
            "description": "Panel administrativo accesible sin autenticacion.",
        },
        {
            "title": "Debug info",
            "risk": "Medio",
            "path": "/debug-info",
            "description": "Informacion interna mostrada a cualquier visitante.",
        },
        {
            "title": "Scanner YARA",
            "risk": "Educativo",
            "path": "/scan",
            "description": "Analiza archivos subidos con reglas YARA locales.",
        },
    ]


@app.route("/")
def index():
    return render_template("index.html", labs=get_lab_cards())


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    debug_query = None

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db()
        cursor = conn.cursor()

        # Vulnerable a SQLi a proposito: usar solo en laboratorio local.
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        debug_query = query
        print("DEBUG QUERY:", query)
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()

        if user:
            session["username"] = user["username"]
            return redirect(url_for("dashboard"))

        error = "Usuario o password incorrectos"

    return render_template("login.html", error=error, debug_query=debug_query)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))

    return render_template("dashboard.html", user=session["username"])


@app.route("/upload", methods=["GET", "POST"])
def upload_file():
    message = None
    files = sorted(path.name for path in UPLOAD_FOLDER.iterdir() if path.is_file())

    if request.method == "POST":
        if "file" not in request.files:
            message = "No se subio ningun archivo."
        else:
            file = request.files["file"]
            if file.filename == "":
                message = "Nombre de archivo vacio."
            else:
                # No se valida tipo, extension ni contenido: vulnerabilidad intencional.
                filename = secure_filename(file.filename)
                file.save(UPLOAD_FOLDER / filename)
                message = f"Archivo '{filename}' subido exitosamente."
                files = sorted(path.name for path in UPLOAD_FOLDER.iterdir() if path.is_file())

    return render_template("upload.html", message=message, files=files)


@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


@app.route("/comentarios", methods=["GET", "POST"])
def comentarios():
    conn = get_db()

    if request.method == "POST":
        author = request.form.get("author", "anonimo")
        body = request.form.get("body", "")
        conn.execute("INSERT INTO comments (author, body) VALUES (?, ?)", (author, body))
        conn.commit()
        return redirect(url_for("comentarios"))

    comments = conn.execute("SELECT author, body, created_at FROM comments ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("comentarios.html", comments=comments)


@app.route("/admin")
def admin():
    conn = get_db()
    users = conn.execute("SELECT id, username, password FROM users ORDER BY id").fetchall()
    conn.close()

    secrets = {
        "api_key": "sk-lab-demo-123456",
        "backup_path": str(BASE_DIR / "backups" / "db-backup.sqlite"),
        "internal_host": "10.10.10.5",
    }
    return render_template("admin.html", users=users, secrets=secrets)


@app.route("/debug-info")
def debug_info():
    info = {
        "debug": app.debug,
        "secret_key": app.secret_key,
        "database": str(DB_PATH),
        "upload_folder": str(UPLOAD_FOLDER),
        "python_path": os.environ.get("PATH", "")[:260],
        "current_user": session.get("username", "anonimo"),
    }
    return render_template("debug_info.html", info=info)


@app.route("/scan", methods=["GET", "POST"])
def scan():
    result = None
    error = None
    rules_path = RULES_FOLDER / "lab_rules.yar"

    if request.method == "POST":
        uploaded = request.files.get("file")
        if yara is None:
            error = "yara-python no esta instalado en esta venv."
        elif not rules_path.exists():
            error = f"No existe la regla {rules_path}."
        elif uploaded is None or uploaded.filename == "":
            error = "Selecciona un archivo para analizar."
        else:
            filename = secure_filename(uploaded.filename)
            target = UPLOAD_FOLDER / filename
            uploaded.save(target)
            rules = yara.compile(filepath=str(rules_path))
            matches = rules.match(str(target))
            result = {
                "filename": filename,
                "matches": [match.rule for match in matches],
            }

    return render_template("scan.html", result=result, error=error, yara_enabled=yara is not None)


if __name__ == "__main__":
    app.run(debug=True)
