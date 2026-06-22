# VulnFlask

Laboratorio local de ciberseguridad etica hecho con Flask. La aplicacion contiene vulnerabilidades intencionales para practicar pruebas web, leer codigo inseguro y entender como se explotan fallos comunes en un entorno controlado.

> No uses este proyecto en produccion ni contra sistemas sin autorizacion.

## Modulos incluidos

| Ruta | Laboratorio | Que demuestra |
| --- | --- | --- |
| `/` | Panel de laboratorios | Navegacion principal del proyecto |
| `/login` | SQL Injection | Query SQL construida con interpolacion de strings |
| `/dashboard` | Sesion vulnerable | Panel protegido por un login inseguro |
| `/upload` | Upload inseguro | Archivos sin validacion de tipo, extension ni contenido |
| `/uploads/<archivo>` | Archivos expuestos | Acceso directo a archivos subidos |
| `/comentarios` | XSS persistente | Comentarios guardados y renderizados con `safe` |
| `/admin` | Broken access control | Panel admin accesible sin autenticacion |
| `/debug-info` | Information disclosure | Secret key, rutas internas y datos de entorno |
| `/scan` | YARA scanner | Analisis basico de archivos con reglas locales |

## Instalacion con venv

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python create_db.py
python app.py
```

Si PowerShell bloquea la activacion:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

## Pruebas rapidas

SQLi en `/login`:

```text
Usuario: admin' --
Password: cualquiera
```

XSS persistente en `/comentarios`:

```html
<script>alert(1)</script>
```

YARA en `/scan`:

Sube un `.txt` con este contenido:

```text
powershell -nop -w hidden
```

La regla `rules/lab_rules.yar` deberia detectar `Windows_Command_Strings`.

## Estructura

```text
vulnflask/
  app.py
  create_db.py
  db.db
  requirements.txt
  rules/
    lab_rules.yar
  static/
    style.css
  templates/
  uploads/
```

## Nota

El proyecto mantiene malas practicas a proposito: passwords en texto plano, secret key hardcodeada, SQLi, XSS, rutas sin auth, debug expuesto y upload inseguro. La idea es aprender a reconocerlas y luego crear versiones seguras para comparar.
