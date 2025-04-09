# 🧠 VulnFlask - Laboratorio de Ciberseguridad Ética en Flask

**VulnFlask** es una aplicación web vulnerable desarrollada con Python y Flask, creada con fines educativos y de entrenamiento en **pentesting ético**, análisis de vulnerabilidades y pruebas ofensivas.

> ❗ Este proyecto simula un entorno inseguro y **no debe usarse en producción ni contra sistemas sin autorización**.

---

## 🚀 Funcionalidades

- Sistema de login vulnerable a inyección SQL
- Formulario de subida de archivos sin validación
- Formulario de comentarios vulnerable a XSS persistente
- Ruta `/admin` sin autenticación
- Exposición de archivos subidos al navegador
- Ejecución de comandos (simulación de RCE)
- Variables de entorno y errores visibles
- Cookies sin protección
- Y más...

---

## 🧪 Vulnerabilidades incluidas

| #  | Vulnerabilidad                  | Tipo               |
|----|--------------------------------|--------------------|
| 1  | Inyección SQL (SQLi)           | Autenticación      |
| 2  | Subida de archivos             | Sin validación     |
| 3  | XSS (Cross-Site Scripting)     | Persistente        |
| 4  | Ruta `/admin` sin auth         | Acceso directo     |
| 5  | Fugas de errores               | Debug info         |
| 6  | Secret key visible             | Código fuente      |
| 7  | Sin protección CSRF            | Formularios        |
| 8  | Headers inseguros              | Configuración HTTP |
| 9  | Enumeración de usuarios        | Ruta pública       |
| 10 | Fuerza bruta sin bloqueo       | Login              |
| 11 | Campos ocultos manipulables    | HTML forms         |
| 12 | Cookies no seguras             | Sesión             |
| 13 | IDOR                           | Manipulación de ID |
| 14 | Ruta `/debug-info` expuesta    | Variables internas |
| 15 | Logs sensibles                 | Archivos accesibles|

---

## ⚙️ Instalación

1. Cloná el repositorio:

```bash
git clone https://github.com/menet58/vulnflask.git
cd vulnflask
```
2. Instalá las dependencias:
```bash
pip install -r requirements.txt
```
3. Ejecutá el script para crear la base de datos:
```bash
python create_db.py
```
4. Iniciá la aplicación:
```bash
python app.py
```
📂 Estructura del proyecto
```php
vulnflask/
├── app.py                  # Aplicación principal
├── init_db.py              # Crea la base de datos con usuarios de prueba
├── db.db                   # Base de datos SQLite
├── templates/              # Archivos HTML
├── static/                 # Archivos estáticos (opcional)
├── uploads/                # Archivos subidos (vulnerables)
├── requirements.txt
└── README.md
```
📍 Rutas de interés
- / → Página principal

- /login → Formulario vulnerable a SQLi

- /dashboard → Panel de usuario

- /upload → Subida de archivos sin validación

- /comentarios → XSS persistente

- /admin → Ruta sin autenticación (info sensible)
  
- /uploads/<archivo> → Acceso directo a archivos subidos

- /debug-info → Información interna simulada

⚠️ Disclaimer legal
Este proyecto está diseñado exclusivamente para propósitos educativos y de laboratorio personal.
El uso de este código en sistemas sin consentimiento explícito es ilegal y no está respaldado por el autor.

Siempre hacé pentesting con ética y autorización.


👨‍💻 Autor
Desarrollado con ❤️ por menet58
