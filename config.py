import os

# 🔐 Clave secreta (vulnerable por estar en texto plano)
# En producción, usar variable de entorno
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "superinseguro")

# 📁 Ruta donde se subirán archivos
UPLOAD_FOLDER = "uploads"

# 🧪 Modo debug activado solo si se desea ver errores
DEBUG = True

# 🍪 Opciones de cookies (deja algunas inseguras a propósito para pruebas)
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = False  # Cambiar a True si usás HTTPS real

# 🚫 Extensiones permitidas (no aplicamos filtro aún, solo ejemplo)
ALLOWED_EXTENSIONS = set(['txt', 'jpg', 'png', 'html', 'php', 'js', 'exe', 'py'])
