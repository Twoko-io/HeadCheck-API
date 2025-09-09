# HeadCheck API

**Audit & grade API security headers** (HSTS, CSP, XFO, Referrer-Policy, Permissions-Policy) con semántica real de API: custom headers, JSON bodies, tokens, CORS preflight y batch targets.

---

## 📌 ¿Qué es?

**HeadCheck API** es un validador de cabeceras de seguridad orientado a **APIs** (no páginas web).  
A diferencia de los scanners genéricos, permite:

- ✅ Enviar métodos reales (`GET/POST/PUT/PATCH/DELETE/OPTIONS/HEAD`)
- ✅ Incluir headers arbitrarios (ej. `Authorization`, `x-tenant-id`)
- ✅ Enviar cuerpos `JSON` o `x-www-form-urlencoded`
- ✅ Simular preflight **CORS** (`OPTIONS` + `Origin/Access-Control-Request-*`)
- ✅ Ejecutar en batch (archivo de URLs, filtros) y exportar JSON para pipelines
- ✅ Generar un **grade estilo SecurityHeaders (A+…F)** y un **Security Score estricto**

---

## ✨ Características

- Perfil **SecurityHeaders (SH)** por defecto con *grade* y recomendaciones
- Perfil **estricto** opcional con score ponderado y estados `OK/WARN/FAIL`
- Criterio de éxito configurable (por defecto `2xx`; soporta `3xx`, rangos, listas)
- Batch: archivo de URLs/paths + filtros por `substring` o `regex`
- Presets de headers desde archivos (`JSON` o `k: v`) o CLI
- Detección automática de **Content-Type**
- Modo *browserish* opcional (`User-Agent`, `Accept-Language`, `Accept-Encoding`)
- Proxy para **Burp/ZAP**, TLS inseguro para entornos de prueba
- Salida **JSON estable para CI/CD**

---

## ⚙️ Instalación

📦 Publicación sugerida en PyPI como `headcheck-api`.  
Mientras tanto, uso desde fuente:

```bash
git clone https://github.com/<tu-org>/headcheck-api.git
cd headcheck-api
python -m venv .venv

# Activar entorno
# Linux/macOS
source .venv/bin/activate
# Windows
.venv\Scripts\activate

# Instalar dependencias
python -m pip install -U pip
# (stdlib-only, si usas 'requests' instálalo aquí)

# Ejecuta
python3 headcheck-api.py --help

