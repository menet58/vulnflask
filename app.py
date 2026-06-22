from pathlib import Path
import os
import sqlite3

from flask import Flask, redirect, render_template, request, send_from_directory, session, url_for
from werkzeug.utils import secure_filename

# YARA es opcional: si no esta instalado, el resto del laboratorio sigue funcionando.
try:
    import yara
except ImportError:
    yara = None


# Rutas base del proyecto. Usar Path evita problemas con separadores de Windows/Linux.
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "db.db"
UPLOAD_FOLDER = BASE_DIR / "uploads"
LEVEL_UPLOAD_FOLDER = BASE_DIR / "level_uploads"
RULES_FOLDER = BASE_DIR / "rules"

# Configuracion principal de Flask.
app = Flask(__name__)
app.secret_key = "superinseguro"  # Intencionalmente debil para el laboratorio.
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Asegura que existan las carpetas que la app usa para subir archivos y leer reglas.
UPLOAD_FOLDER.mkdir(exist_ok=True)
LEVEL_UPLOAD_FOLDER.mkdir(exist_ok=True)
RULES_FOLDER.mkdir(exist_ok=True)


def get_db():
    # Abre una conexion nueva a SQLite y permite leer columnas por nombre.
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_level_tables():
    # Crea tablas auxiliares usadas solo por los laboratorios nuevos por nivel.
    conn = get_db()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS level_comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            level INTEGER NOT NULL,
            author TEXT NOT NULL,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.commit()
    conn.close()


def get_lab_cards():
    # Tarjetas visibles en la portada. Cada una apunta a un laboratorio practico.
    return [
        {
            "title": "SQL Injection",
            "risk": "Critico",
            "level": 4,
            "path": "/login",
            "description": "Login con consulta SQL construida por string interpolation.",
        },
        {
            "title": "Upload inseguro",
            "risk": "Alto",
            "level": 3,
            "path": "/upload",
            "description": "Subida de archivos sin validacion de extension, MIME ni contenido.",
        },
        {
            "title": "XSS persistente",
            "risk": "Alto",
            "level": 3,
            "path": "/comentarios",
            "description": "Comentarios guardados en base de datos y renderizados sin escape.",
        },
        {
            "title": "Admin expuesto",
            "risk": "Medio",
            "level": 2,
            "path": "/admin",
            "description": "Panel administrativo accesible sin autenticacion.",
        },
        {
            "title": "Debug info",
            "risk": "Medio",
            "level": 2,
            "path": "/debug-info",
            "description": "Informacion interna mostrada a cualquier visitante.",
        },
        {
            "title": "Scanner YARA",
            "risk": "Educativo",
            "level": 1,
            "path": "/scan",
            "description": "Analiza archivos subidos con reglas YARA locales.",
        },
    ]


def get_security_levels():
    # Guia de dificultad: cada nivel contiene practicas concretas para seguir paso a paso.
    return [
        {
            "id": 1,
            "name": "Nivel 1 - Basico",
            "tag": "Sin impacto critico",
            "summary": "Reconocimiento, lectura de respuestas y analisis de archivos sin explotar fallos graves.",
            "defenses": ["Inventario de rutas", "Mensajes de error controlados", "Reglas YARA simples"],
            "practice": ["Visitar rutas", "Subir un .txt limpio", "Escanear strings con YARA"],
            "activities": [
                {
                    "title": "Reconocer rutas del laboratorio",
                    "route": "/",
                    "goal": "Entender que modulos existen antes de atacar.",
                    "steps": [
                        "Abre la portada.",
                        "Anota las rutas visibles.",
                        "Clasifica cada ruta por riesgo: bajo, medio, alto o critico.",
                    ],
                    "payload": "No requiere payload.",
                    "observe": "La portada revela rutas utiles para continuar el reconocimiento.",
                    "defense": "En una app real, evita exponer paneles internos o rutas sensibles innecesarias.",
                },
                {
                    "title": "Escanear strings con YARA",
                    "route": "/scan",
                    "goal": "Detectar texto sospechoso dentro de un archivo subido.",
                    "steps": [
                        "Crea un archivo .txt de prueba.",
                        "Incluye una palabra como powershell o cmd.exe.",
                        "Subelo en el scanner YARA y revisa la coincidencia.",
                    ],
                    "payload": "powershell -nop -w hidden",
                    "observe": "La regla Windows_Command_Strings deberia aparecer en el resultado.",
                    "defense": "YARA ayuda a clasificar archivos, pero no reemplaza validacion ni sandboxing.",
                },
            ],
        },
        {
            "id": 2,
            "name": "Nivel 2 - Medio",
            "tag": "Exposicion de informacion",
            "summary": "Rutas mal protegidas y datos internos visibles para usuarios sin privilegios.",
            "defenses": ["Autenticacion obligatoria", "Autorizacion por rol", "Ocultar debug en produccion"],
            "practice": ["Revisar /admin", "Revisar /debug-info", "Identificar secretos simulados"],
            "activities": [
                {
                    "title": "Abrir admin sin sesion",
                    "route": "/admin",
                    "goal": "Comprobar si una ruta sensible exige autenticacion.",
                    "steps": [
                        "Cierra sesion si estabas logueado.",
                        "Abre /admin directamente.",
                        "Revisa si puedes ver usuarios y secretos simulados.",
                    ],
                    "payload": "No requiere payload.",
                    "observe": "La ruta responde aunque no seas admin.",
                    "defense": "Exigir login y verificar rol antes de entregar datos sensibles.",
                },
                {
                    "title": "Buscar informacion interna",
                    "route": "/debug-info",
                    "goal": "Identificar datos internos que ayudan a un atacante.",
                    "steps": [
                        "Abre /debug-info.",
                        "Busca rutas locales, secret key y variables expuestas.",
                        "Piensa que datos no deberian llegar al navegador.",
                    ],
                    "payload": "No requiere payload.",
                    "observe": "La pagina muestra configuracion interna de la app.",
                    "defense": "Desactivar debug publico y devolver errores genericos.",
                },
            ],
        },
        {
            "id": 3,
            "name": "Nivel 3 - Alto",
            "tag": "Entrada peligrosa",
            "summary": "Datos del usuario entran a la app sin validacion suficiente.",
            "defenses": ["Validar extension y MIME", "Escapar HTML", "Limitar tamano de archivos"],
            "practice": ["Probar XSS persistente", "Subir HTML o TXT sospechoso", "Comparar input vs output"],
            "activities": [
                {
                    "title": "Probar XSS persistente",
                    "route": "/comentarios",
                    "goal": "Ver que pasa cuando HTML del usuario se renderiza sin escape.",
                    "steps": [
                        "Abre /comentarios.",
                        "Guarda un comentario con una etiqueta HTML o script.",
                        "Recarga la pagina y observa si el contenido sigue ejecutandose o renderizandose.",
                    ],
                    "payload": "<script>alert(1)</script>",
                    "observe": "El comentario queda guardado y se muestra usando el filtro safe.",
                    "defense": "Escapar salida HTML y usar una politica CSP restrictiva.",
                },
                {
                    "title": "Subir archivo sin validacion",
                    "route": "/upload",
                    "goal": "Comprobar que la app acepta archivos sin revisar tipo ni contenido.",
                    "steps": [
                        "Crea un archivo .html o .txt.",
                        "Subelo desde /upload.",
                        "Abre el enlace generado en /uploads/<archivo>.",
                    ],
                    "payload": "<h1>archivo controlado por usuario</h1>",
                    "observe": "El archivo queda accesible desde el navegador.",
                    "defense": "Validar extension, MIME, tamano, contenido y servir uploads desde dominio aislado.",
                },
            ],
        },
        {
            "id": 4,
            "name": "Nivel 4 - Extremo",
            "tag": "Compromiso directo",
            "summary": "Fallos que pueden saltarse autenticacion o comprometer el flujo principal.",
            "defenses": ["Consultas parametrizadas", "Hash de passwords", "Rate limiting", "CSRF tokens"],
            "practice": ["Probar payload SQLi", "Entrar sin password valida", "Leer la query debug generada"],
            "activities": [
                {
                    "title": "Bypass de login con SQLi",
                    "route": "/login",
                    "goal": "Saltar la autenticacion manipulando la consulta SQL.",
                    "steps": [
                        "Abre /login.",
                        "Escribe el payload en el campo usuario.",
                        "Pon cualquier texto en password y envia el formulario.",
                    ],
                    "payload": "admin' --",
                    "observe": "La query debug queda cortada por el comentario SQL y puede devolver el usuario admin.",
                    "defense": "Usar parametros SQL, hash de passwords y mensajes de error genericos.",
                },
                {
                    "title": "Analizar la fuga de query",
                    "route": "/login",
                    "goal": "Entender por que imprimir queries ayuda a explotar el fallo.",
                    "steps": [
                        "Intenta un login invalido.",
                        "Revisa el bloque DEBUG QUERY.",
                        "Compara como cambia la query al insertar comillas o comentarios.",
                    ],
                    "payload": "' OR '1'='1' --",
                    "observe": "La app muestra la estructura exacta de la consulta vulnerable.",
                    "defense": "No mostrar consultas internas y registrar logs sensibles solo en entorno seguro.",
                },
            ],
        },
    ]


def get_level_resources():
    # Recursos extra por dificultad: checklists, payloads y retos para practicar.
    return {
        1: {
            "title": "Recursos Nivel 1",
            "difficulty": "Baja",
            "focus": "Reconocimiento y deteccion basica",
            "items": [
                {
                    "name": "Checklist de reconocimiento",
                    "kind": "Checklist",
                    "content": [
                        "Identificar rutas visibles.",
                        "Anotar formularios y metodos HTTP.",
                        "Detectar mensajes de error o informacion tecnica.",
                        "Separar rutas publicas de rutas sensibles.",
                    ],
                },
                {
                    "name": "Strings para YARA",
                    "kind": "Payloads seguros",
                    "content": ["powershell", "cmd.exe", "curl ", "base64", "eval("],
                },
                {
                    "name": "Mini reto",
                    "kind": "Practica",
                    "content": [
                        "Sube un .txt con una string sospechosa.",
                        "Consigue que el scanner devuelva una coincidencia.",
                        "Explica por que eso no prueba que el archivo sea malware real.",
                    ],
                },
            ],
        },
        2: {
            "title": "Recursos Nivel 2",
            "difficulty": "Media",
            "focus": "Exposicion de informacion y acceso indebido",
            "items": [
                {
                    "name": "Datos que nunca deberian exponerse",
                    "kind": "Checklist",
                    "content": [
                        "Passwords, hashes o tokens.",
                        "Secret keys y API keys.",
                        "Rutas internas del servidor.",
                        "Hosts privados, backups o nombres de usuarios internos.",
                    ],
                },
                {
                    "name": "Pruebas de control de acceso",
                    "kind": "Metodo",
                    "content": [
                        "Probar la ruta sin sesion.",
                        "Probar con usuario normal.",
                        "Probar con rol admin.",
                        "Confirmar que la validacion ocurre en backend.",
                    ],
                },
                {
                    "name": "Mini reto",
                    "kind": "Practica",
                    "content": [
                        "Encuentra tres datos sensibles en /admin o /debug-info.",
                        "Clasifica cada dato por impacto.",
                        "Propone una regla de defensa para cada hallazgo.",
                    ],
                },
            ],
        },
        3: {
            "title": "Recursos Nivel 3",
            "difficulty": "Alta",
            "focus": "Entradas peligrosas, XSS y uploads",
            "items": [
                {
                    "name": "Payloads de XSS controlados",
                    "kind": "Payloads",
                    "content": [
                        "<script>alert(1)</script>",
                        "<img src=x onerror=alert(1)>",
                        "<strong>HTML persistente</strong>",
                    ],
                },
                {
                    "name": "Checklist de upload",
                    "kind": "Checklist",
                    "content": [
                        "Validar extension permitida.",
                        "Verificar MIME real.",
                        "Limitar tamano.",
                        "Renombrar archivo.",
                        "Servir desde almacenamiento aislado.",
                    ],
                },
                {
                    "name": "Mini reto",
                    "kind": "Practica",
                    "content": [
                        "Guarda un comentario que persista.",
                        "Sube un archivo HTML de prueba.",
                        "Documenta que input entro y como salio en la respuesta.",
                    ],
                },
            ],
        },
        4: {
            "title": "Recursos Nivel 4",
            "difficulty": "Extrema",
            "focus": "SQL Injection y bypass de autenticacion",
            "items": [
                {
                    "name": "Payloads SQLi de laboratorio",
                    "kind": "Payloads",
                    "content": ["admin' --", "' OR '1'='1' --", "admin' OR 1=1 --"],
                },
                {
                    "name": "Defensas obligatorias",
                    "kind": "Checklist",
                    "content": [
                        "Consultas parametrizadas.",
                        "Passwords con hash fuerte.",
                        "Rate limiting en login.",
                        "Mensajes de error genericos.",
                        "Logs internos no visibles al usuario.",
                    ],
                },
                {
                    "name": "Mini reto",
                    "kind": "Practica",
                    "content": [
                        "Consigue entrar sin password valida.",
                        "Explica que parte de la query fue manipulada.",
                        "Reescribe mentalmente la consulta usando parametros.",
                    ],
                },
            ],
        },
    }


def get_level_modules():
    # Los mismos modulos aparecen en cada nivel, pero la exigencia sube con la dificultad.
    return {
        1: [
            {
                "name": "Login",
                "route": "/login",
                "objective": "Reconocer campos, mensajes de error y flujo normal de autenticacion.",
                "task": "Entrar con credenciales conocidas como admin/admin y observar la respuesta.",
                "payload": "admin / admin",
                "observe": "El login crea sesion y redirige al dashboard.",
            },
            {
                "name": "Upload",
                "route": "/upload",
                "objective": "Identificar como se sube y publica un archivo simple.",
                "task": "Subir un .txt limpio y abrirlo desde la lista de archivos expuestos.",
                "payload": "archivo.txt -> hola laboratorio",
                "observe": "El archivo queda disponible en /uploads/<archivo>.",
            },
            {
                "name": "Comentarios / XSS",
                "route": "/comentarios",
                "objective": "Distinguir texto normal de contenido HTML.",
                "task": "Guardar un comentario sin payload y revisar que persiste.",
                "payload": "hola desde nivel 1",
                "observe": "El comentario queda almacenado en la base de datos.",
            },
            {
                "name": "YARA",
                "route": "/scan",
                "objective": "Detectar strings simples en archivos de prueba.",
                "task": "Subir un .txt con una palabra detectada por las reglas.",
                "payload": "powershell",
                "observe": "Aparece una coincidencia de regla YARA.",
            },
        ],
        2: [
            {
                "name": "Login",
                "route": "/login",
                "objective": "Comparar errores y detectar informacion util para enumeracion.",
                "task": "Probar usuarios validos e invalidos y revisar si el mensaje cambia.",
                "payload": "admin / incorrecto",
                "observe": "El mensaje es generico, pero el debug puede revelar estructura interna.",
            },
            {
                "name": "Upload",
                "route": "/upload",
                "objective": "Comprobar si la app restringe extension o tipo de archivo.",
                "task": "Subir .txt, .html y un nombre con espacios para ver como se guardan.",
                "payload": "reporte prueba.html",
                "observe": "secure_filename limpia el nombre, pero no valida contenido.",
            },
            {
                "name": "Comentarios / XSS",
                "route": "/comentarios",
                "objective": "Probar si el HTML se guarda como texto o se interpreta.",
                "task": "Guardar una etiqueta HTML inofensiva.",
                "payload": "<strong>comentario marcado</strong>",
                "observe": "Si se renderiza en negrita, la salida no esta escapando HTML.",
            },
            {
                "name": "Admin / Debug",
                "route": "/admin",
                "objective": "Buscar rutas sensibles accesibles sin permiso.",
                "task": "Abrir /admin y /debug-info sin iniciar sesion.",
                "payload": "No requiere payload.",
                "observe": "Se exponen usuarios, rutas internas y secretos simulados.",
            },
        ],
        3: [
            {
                "name": "Login",
                "route": "/login",
                "objective": "Detectar si caracteres especiales rompen la consulta.",
                "task": "Probar comillas simples y observar la query debug.",
                "payload": "'",
                "observe": "La query queda mal formada o muestra claramente donde entra el input.",
            },
            {
                "name": "Upload",
                "route": "/upload",
                "objective": "Subir contenido activo o interpretable por navegador.",
                "task": "Subir un archivo HTML y abrirlo desde /uploads.",
                "payload": "<h1>archivo controlado</h1>",
                "observe": "El navegador puede renderizar contenido controlado por el usuario.",
            },
            {
                "name": "Comentarios / XSS",
                "route": "/comentarios",
                "objective": "Confirmar XSS persistente con un payload controlado.",
                "task": "Guardar un payload que ejecute JavaScript en el navegador.",
                "payload": "<script>alert(1)</script>",
                "observe": "El script persiste y se ejecuta al cargar comentarios.",
            },
            {
                "name": "YARA + Upload",
                "route": "/scan",
                "objective": "Combinar archivo subido con deteccion de strings sospechosas.",
                "task": "Subir un archivo con comandos y revisar coincidencias.",
                "payload": "cmd.exe /c whoami",
                "observe": "YARA detecta la string, pero el upload sigue aceptando el archivo.",
            },
        ],
        4: [
            {
                "name": "Login",
                "route": "/login",
                "objective": "Saltar autenticacion mediante SQL Injection.",
                "task": "Usar un comentario SQL para ignorar la condicion del password.",
                "payload": "admin' --",
                "observe": "La app puede iniciar sesion sin password valida.",
            },
            {
                "name": "Upload",
                "route": "/upload",
                "objective": "Evaluar el peor caso de un upload sin validacion.",
                "task": "Subir HTML con script y abrirlo desde la ruta publica.",
                "payload": "<script>alert('upload')</script>",
                "observe": "El contenido subido queda servido por la app.",
            },
            {
                "name": "Comentarios / XSS",
                "route": "/comentarios",
                "objective": "Analizar impacto de XSS persistente en usuarios futuros.",
                "task": "Guardar un payload y comprobar que afecta cada recarga.",
                "payload": "<img src=x onerror=alert('xss')>",
                "observe": "El payload queda almacenado y se dispara para quien visite la pagina.",
            },
            {
                "name": "Cadena de ataque",
                "route": "/debug-info",
                "objective": "Encadenar informacion expuesta con explotacion.",
                "task": "Usar debug/admin para recolectar contexto y luego probar SQLi.",
                "payload": "' OR '1'='1' --",
                "observe": "La fuga de informacion facilita construir payloads mas precisos.",
            },
        ],
    }


def get_new_level_modules():
    # Laboratorios nuevos: cada nivel tiene login, upload, XSS y comentarios propios.
    modules = {
        1: [
            {
                "name": "Login Nivel 1",
                "route": "/lab/nivel/1/login",
                "objective": "Practicar autenticacion basica sin explotar SQLi.",
                "task": "Entrar con usuario demo y revisar mensajes normales.",
                "payload": "aprendiz / nivel1",
                "observe": "La consulta usa parametros y no muestra datos internos.",
            },
            {
                "name": "Upload Nivel 1",
                "route": "/lab/nivel/1/upload",
                "objective": "Subir solo archivos .txt pequenos.",
                "task": "Subir un archivo de texto y confirmar que se guarda.",
                "payload": "notas.txt",
                "observe": "Solo acepta .txt y limita el tamano.",
            },
            {
                "name": "XSS Nivel 1",
                "route": "/lab/nivel/1/xss",
                "objective": "Ver como se escapa HTML correctamente.",
                "task": "Enviar una etiqueta HTML y observar que se muestra como texto.",
                "payload": "<strong>hola</strong>",
                "observe": "El navegador no interpreta el HTML.",
            },
            {
                "name": "Comentarios Nivel 1",
                "route": "/lab/nivel/1/comentarios",
                "objective": "Guardar comentarios normales escapados.",
                "task": "Publicar texto simple y revisar persistencia.",
                "payload": "comentario normal",
                "observe": "El comentario persiste sin ejecutar HTML.",
            },
        ],
        2: [
            {
                "name": "Login Nivel 2",
                "route": "/lab/nivel/2/login",
                "objective": "Detectar enumeracion por mensajes diferentes.",
                "task": "Probar usuario existente y usuario inexistente.",
                "payload": "analista / password-malo",
                "observe": "El mensaje revela si el usuario existe.",
            },
            {
                "name": "Upload Nivel 2",
                "route": "/lab/nivel/2/upload",
                "objective": "Comprobar validacion debil por extension.",
                "task": "Subir .txt y .html para comparar respuesta.",
                "payload": "reporte.html",
                "observe": "El servidor confia demasiado en el nombre del archivo.",
            },
            {
                "name": "XSS Nivel 2",
                "route": "/lab/nivel/2/xss",
                "objective": "Probar reflejo de entrada todavia escapada.",
                "task": "Enviar HTML y buscar si se refleja en la respuesta.",
                "payload": "<em>prueba</em>",
                "observe": "Hay reflejo de input, pero aun no se ejecuta.",
            },
            {
                "name": "Comentarios Nivel 2",
                "route": "/lab/nivel/2/comentarios",
                "objective": "Detectar almacenamiento de HTML inofensivo.",
                "task": "Guardar una etiqueta de formato y observar salida.",
                "payload": "<strong>texto marcado</strong>",
                "observe": "Sirve para comparar escape vs renderizado.",
            },
        ],
        3: [
            {
                "name": "Login Nivel 3",
                "route": "/lab/nivel/3/login",
                "objective": "Detectar SQLi viendo la query debug.",
                "task": "Probar comilla simple en usuario.",
                "payload": "'",
                "observe": "La app muestra una query vulnerable como pista.",
            },
            {
                "name": "Upload Nivel 3",
                "route": "/lab/nivel/3/upload",
                "objective": "Subir HTML que el navegador pueda renderizar.",
                "task": "Subir un .html y abrirlo desde la lista.",
                "payload": "<h1>controlado</h1>",
                "observe": "El archivo queda expuesto desde una ruta publica.",
            },
            {
                "name": "XSS Nivel 3",
                "route": "/lab/nivel/3/xss",
                "objective": "Probar XSS reflejado.",
                "task": "Enviar un payload que ejecuta JavaScript.",
                "payload": "<script>alert(1)</script>",
                "observe": "El input se renderiza sin escape.",
            },
            {
                "name": "Comentarios Nivel 3",
                "route": "/lab/nivel/3/comentarios",
                "objective": "Probar XSS persistente.",
                "task": "Guardar un script y recargar comentarios.",
                "payload": "<script>alert('persistente')</script>",
                "observe": "El payload queda guardado.",
            },
        ],
        4: [
            {
                "name": "Login Nivel 4",
                "route": "/lab/nivel/4/login",
                "objective": "Hacer bypass completo de autenticacion con SQLi.",
                "task": "Comentar la parte del password.",
                "payload": "admin' --",
                "observe": "El login puede aceptar una password falsa.",
            },
            {
                "name": "Upload Nivel 4",
                "route": "/lab/nivel/4/upload",
                "objective": "Evaluar impacto extremo de upload sin controles.",
                "task": "Subir HTML con script y abrirlo desde /level-uploads.",
                "payload": "<script>alert('nivel4')</script>",
                "observe": "El archivo controlado queda servido por la app.",
            },
            {
                "name": "XSS Nivel 4",
                "route": "/lab/nivel/4/xss",
                "objective": "Probar XSS reflejado con robo simulado de cookie.",
                "task": "Enviar payload que lee document.cookie en laboratorio.",
                "payload": "<img src=x onerror=alert(document.cookie)>",
                "observe": "Muestra el impacto de ejecutar JS en contexto de la app.",
            },
            {
                "name": "Comentarios Nivel 4",
                "route": "/lab/nivel/4/comentarios",
                "objective": "XSS persistente de mayor impacto.",
                "task": "Guardar payload que se dispara para cualquier visitante.",
                "payload": "<img src=x onerror=alert('comentarios-n4')>",
                "observe": "El ataque persiste hasta que se limpie la base de datos.",
            },
        ],
    }
    return modules


@app.route("/")
def index():
    # Portada con todos los laboratorios y acceso a la escalera de niveles.
    return render_template("index.html", labs=get_lab_cards(), levels=get_security_levels())


@app.route("/niveles")
def niveles():
    # Muestra los cuatro niveles de seguridad como guia de estudio.
    return render_template("niveles.html", levels=get_security_levels(), selected_level=None)


@app.route("/nivel/<int:level_id>")
def nivel(level_id):
    # Cada nivel tiene su propio HTML para poder personalizar la practica.
    levels = get_security_levels()
    selected_level = next((level for level in levels if level["id"] == level_id), None)

    if selected_level is None:
        return redirect(url_for("niveles"))

    labs = [lab for lab in get_lab_cards() if lab["level"] == level_id]
    return render_template(
        f"nivel{level_id}.html",
        levels=levels,
        selected_level=selected_level,
        labs=labs,
        resources=get_level_resources()[level_id],
        modules=get_new_level_modules()[level_id],
    )


@app.route("/recursos/nivel/<int:level_id>")
def recursos_nivel(level_id):
    # Pagina de recursos por dificultad: material extra para cada nivel.
    levels = get_security_levels()
    selected_level = next((level for level in levels if level["id"] == level_id), None)
    resources = get_level_resources().get(level_id)

    if selected_level is None or resources is None:
        return redirect(url_for("niveles"))

    return render_template("recursos_nivel.html", selected_level=selected_level, resources=resources)


def get_level_or_redirect(level_id):
    # Valida que el nivel exista antes de entrar a un laboratorio especifico.
    return next((level for level in get_security_levels() if level["id"] == level_id), None)


@app.route("/lab/nivel/<int:level_id>/login", methods=["GET", "POST"])
def level_login(level_id):
    selected_level = get_level_or_redirect(level_id)
    if selected_level is None:
        return redirect(url_for("niveles"))

    error = None
    message = None
    debug_query = None

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        conn = get_db()

        if level_id == 1:
            # Nivel 1: login seguro de practica, sin SQL dinamico.
            user = conn.execute(
                "SELECT * FROM users WHERE username = ? AND password = ?",
                ("aprendiz", "nivel1"),
            ).fetchone()
            if username == "aprendiz" and password == "nivel1" and user is None:
                message = "Login correcto: flujo seguro basico completado."
            elif username == "aprendiz" and password == "nivel1":
                message = "Login correcto."
            else:
                error = "Credenciales incorrectas."

        elif level_id == 2:
            # Nivel 2: enumeracion de usuario por mensajes distintos.
            user_exists = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            if user_exists is None:
                error = "El usuario no existe."
            elif password != user_exists["password"]:
                error = "Password incorrecta para usuario existente."
            else:
                message = f"Login correcto como {username}."

        elif level_id == 3:
            # Nivel 3: SQL dinamico con debug visible para estudiar la inyeccion.
            debug_query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
            try:
                user = conn.execute(debug_query).fetchone()
                message = f"Login correcto como {user['username']}." if user else None
                error = None if user else "Credenciales incorrectas."
            except sqlite3.Error as exc:
                error = f"Error SQL visible: {exc}"

        else:
            # Nivel 4: SQLi explotable para bypass de autenticacion.
            debug_query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
            try:
                user = conn.execute(debug_query).fetchone()
                message = f"Bypass logrado como {user['username']}." if user else None
                error = None if user else "Credenciales incorrectas."
            except sqlite3.Error as exc:
                error = f"Error SQL visible: {exc}"

        conn.close()

    return render_template(
        "level_login.html",
        selected_level=selected_level,
        error=error,
        message=message,
        debug_query=debug_query,
    )


@app.route("/lab/nivel/<int:level_id>/upload", methods=["GET", "POST"])
def level_upload(level_id):
    selected_level = get_level_or_redirect(level_id)
    if selected_level is None:
        return redirect(url_for("niveles"))

    level_folder = LEVEL_UPLOAD_FOLDER / f"nivel{level_id}"
    level_folder.mkdir(parents=True, exist_ok=True)
    message = None
    error = None

    if request.method == "POST":
        uploaded = request.files.get("file")
        if uploaded is None or uploaded.filename == "":
            error = "Selecciona un archivo."
        else:
            filename = secure_filename(uploaded.filename)
            extension = Path(filename).suffix.lower()
            content = uploaded.read()

            if level_id == 1 and (extension != ".txt" or len(content) > 2048):
                error = "Nivel 1 solo acepta .txt de maximo 2 KB."
            elif level_id == 2 and extension not in {".txt", ".html"}:
                error = "Nivel 2 acepta .txt y .html para comparar validacion debil."
            else:
                (level_folder / filename).write_bytes(content)
                message = f"Archivo guardado como {filename}."

    files = sorted(path.name for path in level_folder.iterdir() if path.is_file())
    return render_template("level_upload.html", selected_level=selected_level, message=message, error=error, files=files)


@app.route("/level-uploads/nivel<int:level_id>/<path:filename>")
def level_uploaded_file(level_id, filename):
    selected_level = get_level_or_redirect(level_id)
    if selected_level is None:
        return redirect(url_for("niveles"))

    return send_from_directory(LEVEL_UPLOAD_FOLDER / f"nivel{level_id}", filename)


@app.route("/lab/nivel/<int:level_id>/xss", methods=["GET", "POST"])
def level_xss(level_id):
    selected_level = get_level_or_redirect(level_id)
    if selected_level is None:
        return redirect(url_for("niveles"))

    reflected = ""
    if request.method == "POST":
        reflected = request.form.get("payload", "")

    render_unsafe = level_id >= 3
    return render_template(
        "level_xss.html",
        selected_level=selected_level,
        reflected=reflected,
        render_unsafe=render_unsafe,
    )


@app.route("/lab/nivel/<int:level_id>/comentarios", methods=["GET", "POST"])
def level_comments(level_id):
    selected_level = get_level_or_redirect(level_id)
    if selected_level is None:
        return redirect(url_for("niveles"))

    ensure_level_tables()
    conn = get_db()

    if request.method == "POST":
        author = request.form.get("author", "anonimo")
        body = request.form.get("body", "")
        conn.execute(
            "INSERT INTO level_comments (level, author, body) VALUES (?, ?, ?)",
            (level_id, author, body),
        )
        conn.commit()
        conn.close()
        return redirect(url_for("level_comments", level_id=level_id))

    comments = conn.execute(
        "SELECT author, body, created_at FROM level_comments WHERE level = ? ORDER BY id DESC",
        (level_id,),
    ).fetchall()
    conn.close()

    render_unsafe = level_id >= 3
    return render_template(
        "level_comments.html",
        selected_level=selected_level,
        comments=comments,
        render_unsafe=render_unsafe,
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    # Laboratorio de SQL Injection: recibe usuario/password y arma una query insegura.
    error = None
    debug_query = None

    if request.method == "POST":
        # Datos controlados por el usuario. En una app real se validan y se usan parametros SQL.
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db()
        cursor = conn.cursor()

        # Vulnerable a SQLi a proposito: usar solo en laboratorio local.
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        debug_query = query
        print("DEBUG QUERY:", query)  # Fuga de informacion intencional para ver el ataque.
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()

        if user:
            # Si la consulta devuelve una fila, se crea una sesion Flask.
            session["username"] = user["username"]
            return redirect(url_for("dashboard"))

        error = "Usuario o password incorrectos"

    return render_template("login.html", error=error, debug_query=debug_query)


@app.route("/logout")
def logout():
    # Limpia toda la sesion del navegador.
    session.clear()
    return redirect(url_for("index"))


@app.route("/dashboard")
def dashboard():
    # Esta ruta requiere sesion, pero depende de un login vulnerable.
    if "username" not in session:
        return redirect(url_for("login"))

    return render_template("dashboard.html", user=session["username"])


@app.route("/upload", methods=["GET", "POST"])
def upload_file():
    # Laboratorio de subida insegura: guarda archivos sin validar contenido.
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
    # Expone directamente los archivos subidos. Es util para demostrar riesgo de upload inseguro.
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


@app.route("/comentarios", methods=["GET", "POST"])
def comentarios():
    # Laboratorio XSS persistente: guarda comentarios y luego los muestra sin escape.
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
    # Broken access control: no valida si el usuario esta logueado ni si es admin.
    conn = get_db()
    users = conn.execute("SELECT id, username, password FROM users ORDER BY id").fetchall()
    conn.close()

    # Secretos simulados para practicar identificacion de informacion sensible.
    secrets = {
        "api_key": "sk-lab-demo-123456",
        "backup_path": str(BASE_DIR / "backups" / "db-backup.sqlite"),
        "internal_host": "10.10.10.5",
    }
    return render_template("admin.html", users=users, secrets=secrets)


@app.route("/debug-info")
def debug_info():
    # Information disclosure: muestra datos internos que no deberian exponerse.
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
    # Scanner educativo: usa reglas YARA locales para detectar strings sospechosos.
    result = None
    error = None
    rules_path = RULES_FOLDER / "lab_rules.yar"

    if request.method == "POST":
        # El archivo se guarda primero y luego se analiza con YARA.
        uploaded = request.files.get("file")
        if yara is None:
            error = "yara-python no esta instalado en esta venv."
        elif not rules_path.exists():
            error = f"No existe la regla {rules_path}."
        elif uploaded is None or uploaded.filename == "":
            error = "Selecciona un archivo para analizar."
        else:
            # secure_filename reduce rutas peligrosas, pero no valida si el contenido es seguro.
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
