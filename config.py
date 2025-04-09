import os

SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "superinseguro")  # ⚠️ usar variable de entorno en real
UPLOAD_FOLDER = "uploads"
DEBUG = True  # Cambiar a False en producción
