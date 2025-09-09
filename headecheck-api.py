#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
API Security Header Checker (perfil SecurityHeaders por defecto, salida mínima: SOLO Missing)

Nivel ++:
- Considera HTTP 2xx como éxito por defecto (incluye 202). Personalizable con --success.
- --success "2xx" (default) | "200,202,204" | "2xx,3xx" | "201-204" (rangos) | combinaciones.
- --debug: muestra resumen de estados suprimidos cuando no hay éxitos (o siempre si quieres).
- Control header cliente: --no-client-header / --client-header "K: V".
- Presets genéricos: --headers-file (JSON/TXT), --preset-kv "k=v,...", --preset-override.
- Filtros de objetivos en archivo: --include-substr / --include-regex.
- Accept por defecto: application/json (cambiable con --accept / --accept-any).
- Salida clara: detalle por método + resumen por éxitos (según --success) y opcional + no-éxito si --show-all.

Ejemplos:
  headcheck.py https://api/endpoint --success "2xx,302"
  headcheck.py --urls-file targets.txt --include-substr "/refunds" --debug
  headcheck.py https://api/endpoint --no-client-header
  headcheck.py https://api/endpoint --client-header "X-Env: QA"
"""

import argparse, json, sys, ssl, urllib.parse, os, platform, base64, textwrap, re, collections
from urllib.request import Request, build_opener, ProxyHandler, HTTPSHandler, HTTPRedirectHandler
from urllib.error import URLError, HTTPError

OK, WARN, FAIL = "OK", "WARN", "FAIL"
WRITE_METHODS = {"POST","PUT","PATCH"}
ALL_METHODS = ["OPTIONS","HEAD","GET","POST","PUT","PATCH","DELETE"]

# =======================
# Colores
# =======================
class Colors:
    EN = os.environ.get("NO_COLOR") is None
    RESET = "\033[0m" if EN else ""
    BOLD  = "\033[1m" if EN else ""
    RED   = "\033[31m" if EN else ""
    GREEN = "\033[32m" if EN else ""
    YELLOW= "\033[33m" if EN else ""
    CYAN  = "\033[36m" if EN else ""
    GREY  = "\033[90m" if EN else ""

def enable_win_ansi():
    if platform.system().lower().startswith("win"):
        try:
            import ctypes
            k = ctypes.windll.kernel32
            h = k.GetStdHandle(-11)
            mode = ctypes.c_ulong()
            if k.GetConsoleMode(h, ctypes.byref(mode)):
                k.SetConsoleMode(h, mode.value | 0x0004)
        except Exception:
            pass

# =======================
# Helpers
# =======================
def ensure_scheme(u: str) -> str:
    return u if u.startswith(("http://","https://")) else ("https://" + u)

def url_host_origin(u: str) -> str:
    p = urllib.parse.urlparse(ensure_scheme(u))
    return f"{p.scheme}://{p.netloc}"

def parse_kv_colon(items):
    out = {}
    for it in items or []:
        if ":" in it:
            k, v = it.split(":", 1)
            out[k.strip()] = v.strip()
    return out

def parse_kv_inline_list(items):
    out = {}
    for s in items or []:
        if not s: continue
        pairs = [p.strip() for p in s.split(",") if p.strip()]
        for p in pairs:
            if "=" in p:
                k, v = p.split("=", 1)
            elif ":" in p:
                k, v = p.split(":", 1)
            else:
                continue
            out[k.strip()] = v.strip()
    return out

def parse_single_header(s: str):
    if not s:
        return None
    if ":" in s:
        k, v = s.split(":", 1)
    elif "=" in s:
        k, v = s.split("=", 1)
    else:
        return None
    return (k.strip(), v.strip())

def get_header(headers, name):
    for k in headers:
        if k.lower() == name.lower():
            return headers[k]
    return None

def header_exists_ci(headers: dict, key: str) -> bool:
    kl = key.lower()
    for k in headers:
        if k.lower() == kl:
            return True
    return False

def add_if_absent_ci(headers: dict, key: str, value: str):
    if not header_exists_ci(headers, key):
        headers[key] = value

def set_header_ci(headers: dict, key: str, value: str):
    for k in list(headers.keys()):
        if k.lower() == key.lower():
            del headers[k]
            break
    headers[key] = value

def apply_headers(headers: dict, to_add: dict, override: bool = False):
    for k, v in (to_add or {}).items():
        if override:
            set_header_ci(headers, k, v)
        else:
            add_if_absent_ci(headers, k, v)
    return headers

def infer_content_type_if_needed(headers, body):
    if any(k.lower()=="content-type" for k in headers): return headers
    if not body: return headers
    bt = body.strip()
    if (bt.startswith("{") and bt.endswith("}")) or (bt.startswith("[") and bt.endswith("]")):
        ct = "application/json"
    elif "=" in bt and "&" in bt:
        ct = "application/x-www-form-urlencoded"
    else:
        ct = "text/plain"
    h = dict(headers); h["Content-Type"] = ct; return h

def browserish_headers():
    return {
        "User-Agent": ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"),
        "Accept-Language": "es-CL,es;q=0.9,en;q=0.8",
        "Accept-Encoding": "gzip, deflate"
    }

def smart_oauth_body_if_needed(url: str, body: str, headers: dict):
    if ("/token" in url) and (not body):
        b = "grant_type=client_credentials"
        h = dict(headers); set_header_ci(h, "Content-Type", "application/x-www-form-urlencoded")
        return b, h
    return body, headers

def encode_basic_if_needed(headers: dict, basic: str):
    if not basic: return headers
    if any(k.lower()=="authorization" for k in headers): return headers
    token = base64.b64encode(basic.encode("utf-8")).decode("ascii")
    h = dict(headers); h["Authorization"] = f"Basic {token}"; return h

def add_bearer_if_needed(headers: dict, bearer: str):
    if not bearer: return headers
    if any(k.lower()=="authorization" for k in headers): return headers
    h = dict(headers); h["Authorization"] = f"Bearer {bearer}"; return h

def check_boolean(expr, ok_msg, warn_msg=None, fail_msg=None, remediation=None, weight=1):
    if expr: return {"status": OK, "msg": ok_msg, "fix": None, "weight": weight}
    if fail_msg: return {"status": FAIL, "msg": fail_msg, "fix": remediation, "weight": weight}
    return {"status": WARN, "msg": warn_msg or "Revisar", "fix": remediation, "weight": weight}

def read_lines_file(path):
    items = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#") or s.startswith("//"):
                continue
            items.append(s)
    return items

def join_base_and_path(base_url: str, path: str) -> str:
    base_url = ensure_scheme(base_url.rstrip("/"))
    if not path.startswith("/"):
        path = "/" + path
    return base_url + path

def load_headers_file(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        try:
            data = json.loads(content)
            if isinstance(data, dict):
                return {str(k): str(v) for k, v in data.items()}
        except Exception:
            pass
        preset = {}
        for raw in content.splitlines():
            s = raw.strip()
            if not s or s.startswith("#") or s.startswith("//"):
                continue
            if ":" in s:
                k, v = s.split(":", 1)
            elif "=" in s:
                k, v = s.split("=", 1)
            else:
                continue
            preset[k.strip()] = v.strip()
        return preset
    except Exception as e:
        print(f"[!] No se pudo leer headers file '{path}': {e}", file=sys.stderr)
        return {}

def filter_targets(targets, include_substr, include_regex):
    if not include_substr and not include_regex:
        return targets
    out = []
    for t in targets:
        ok = False
        for s in include_substr or []:
            if s.lower() in t.lower():
                ok = True; break
        if not ok:
            for pat in include_regex or []:
                try:
                    if re.search(pat, t):
                        ok = True; break
                except re.error:
                    continue
        if ok:
            out.append(t)
    return out

# ---------------- Success predicate ----------------
def build_success_pred(success_spec: str):
    """
    success_spec: cadena tipo "2xx" | "200,202,204" | "2xx,3xx" | "201-204" | combinaciones.
    Devuelve función is_success(code:int)->bool y una etiqueta humana.
    """
    if not success_spec:
        # Default: 2xx
        classes = [(200, 299)]
        def pred(c): return 200 <= c <= 299
        return pred, "2xx"

    ranges = []
    label_parts = []
    tokens = [t.strip() for t in success_spec.split(",") if t.strip()]
    for tok in tokens:
        m = re.fullmatch(r"([1-5])xx", tok)
        if m:
            n = int(m.group(1))
            lo, hi = n*100, n*100 + 99
            ranges.append((lo, hi))
            label_parts.append(tok)
            continue
        m = re.fullmatch(r"(\d{3})-(\d{3})", tok)
        if m:
            lo, hi = int(m.group(1)), int(m.group(2))
            if lo > hi: lo, hi = hi, lo
            ranges.append((lo, hi))
            label_parts.append(f"{lo}-{hi}")
            continue
        m = re.fullmatch(r"(\d{3})", tok)
        if m:
            v = int(m.group(1))
            ranges.append((v, v))
            label_parts.append(m.group(1))
            continue
        # token inválido: ignora
    if not ranges:
        ranges = [(200, 299)]
        label_parts = ["2xx"]

    def pred(code):
        try:
            c = int(code)
        except Exception:
            return False
        for lo, hi in ranges:
            if lo <= c <= hi:
                return True
        return False

    return pred, ",".join(label_parts)

# Opener con HTTPS + Redirects + Proxy
def make_opener(verify_tls: bool, proxy_url: str | None):
    ctx = ssl.create_default_context()
    if not verify_tls:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    https_handler = HTTPSHandler(context=ctx)
    redirect_handler = HTTPRedirectHandler()
    if proxy_url:
        ph = ProxyHandler({"http": proxy_url, "https": proxy_url})
        return build_opener(ph, https_handler, redirect_handler)
    return build_opener(https_handler, redirect_handler)

# =======================
# Núcleo de análisis
# =======================
def analyze_headers(opener, url, method, req_headers, body, timeout,
                    origin, acr_method, acr_headers,
                    client_hdr, no_client_header):
    req = Request(url=url, method=method)
    for k, v in req_headers.items():
        req.add_header(k, v)

    # Header de identificación (opcional)
    if not no_client_header:
        if client_hdr:
            k, v = client_hdr
            if not get_header(req_headers, k):
                req.add_header(k, v)
        else:
            if not get_header(req_headers, "X-Client"):
                req.add_header("X-Client", "Twoko-HeaderCheck")

    if method.upper() == "OPTIONS":
        if origin: req.add_header("Origin", origin)
        if acr_method: req.add_header("Access-Control-Request-Method", acr_method)
        if acr_headers: req.add_header("Access-Control-Request-Headers", acr_headers)

    final_url = url
    try:
        data = body.encode("utf-8") if (body and method.upper() in WRITE_METHODS) else None
        resp = opener.open(req, data=data, timeout=timeout)
        status = resp.status
        rh = dict(resp.headers.items())
        final_url = getattr(resp, "geturl", lambda: final_url)()
        _ = resp.read(0)
    except HTTPError as e:
        status = e.code
        rh = dict(e.headers.items()) if e.headers else {}
        try:
            final_url = e.geturl()
        except Exception:
            pass
    except URLError as e:
        raise SystemExit(f"[!] Error de conexión: {e}")
    except Exception as e:
        raise SystemExit(f"[!] Error: {e}")

    findings = []
    def add(find): findings.append(find)

    hsts = get_header(rh, "Strict-Transport-Security")
    add(check_boolean(
        hsts and "max-age=" in hsts and (lambda mv: mv.isdigit() and int(mv) >= 31536000)(
            hsts.split("max-age=")[1].split(";")[0].strip()),
        "HSTS presente con max-age ≥ 31536000.",
        fail_msg="Falta HSTS robusto (o max-age bajo).",
        remediation="Añadir 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' en HTTPS.",
        weight=3
    ))

    csp = get_header(rh, "Content-Security-Policy")
    add(check_boolean(
        csp is not None,
        "CSP presente.",
        fail_msg="Falta CSP.",
        remediation="Definir CSP sin 'unsafe-inline'/'unsafe-eval' y con 'default-src' restrictivo.",
        weight=3
    ))
    csp_has_unsafe = False
    if csp:
        lc = csp.lower()
        csp_has_unsafe = ("'unsafe-inline'" in lc) or ("'unsafe-eval'" in lc)
        add(check_boolean(
            not csp_has_unsafe,
            "CSP sin unsafe-inline/unsafe-eval.",
            warn_msg="CSP contiene 'unsafe-inline' o 'unsafe-eval'.",
            remediation="Eliminar 'unsafe-*'; usar nonces/hashes para inline.",
            weight=2
        ))

    xcto = get_header(rh, "X-Content-Type-Options")
    add(check_boolean(
        xcto and xcto.lower() == "nosniff",
        "X-Content-Type-Options: nosniff presente.",
        fail_msg="Falta X-Content-Type-Options: nosniff.",
        remediation="Agregar 'X-Content-Type-Options: nosniff'.",
        weight=2
    ))

    frame_ok = False
    if csp and "frame-ancestors" in csp:
        frame_ok = ("frame-ancestors 'none'" in csp) or ("frame-ancestors 'self'" in csp)
    xfo = get_header(rh, "X-Frame-Options")
    frame_ok = frame_ok or (xfo and xfo.lower() in ["deny", "sameorigin"])
    add(check_boolean(
        frame_ok,
        "Protección anti-clickjacking (frame-ancestors/XFO) aplicada.",
        fail_msg="Falta protección anti-clickjacking.",
        remediation="Usar CSP 'frame-ancestors ...' o 'X-Frame-Options: DENY/SAMEORIGIN'.",
        weight=2
    ))

    refpol = get_header(rh, "Referrer-Policy")
    add(check_boolean(
        refpol is not None and any(p in refpol.lower() for p in ["no-referrer", "strict-origin", "same-origin", "strict-origin-when-cross-origin"]),
        "Referrer-Policy presente y segura.",
        fail_msg="Falta Referrer-Policy o es débil.",
        remediation="Usar 'no-referrer' o 'strict-origin-when-cross-origin'.",
        weight=1
    ))

    perm = get_header(rh, "Permissions-Policy")
    add(check_boolean(
        perm is not None,
        "Permissions-Policy presente.",
        warn_msg="Falta Permissions-Policy.",
        remediation="Ej.: 'Permissions-Policy: camera=(), geolocation=()'.",
        weight=1
    ))

    essential_present = {
        "hsts": bool(hsts),
        "xcto": bool(xcto and xcto.lower() == "nosniff"),
        "frameprot": bool(frame_ok),
        "csp": bool(csp),
    }
    essentials = sum(1 for v in essential_present.values() if v)
    base_map = {4: "A", 3: "B", 2: "D", 1: "E", 0: "F"}
    sh_grade = base_map.get(essentials, "F")
    if essentials == 4 and (not csp_has_unsafe) and refpol:
        sh_grade = "A+"
    if csp_has_unsafe and sh_grade == "A+":
        sh_grade = "A"

    display_name = {
        "hsts": "Strict-Transport-Security",
        "xcto": "X-Content-Type-Options",
        "frameprot": "X-Frame-Options / CSP frame-ancestors",
        "csp": "Content-Security-Policy",
        "referrer": "Referrer-Policy",
        "permissions": "Permissions-Policy",
    }
    present_sh = [display_name[k] for k, v in essential_present.items() if v]
    extras_present = {"referrer": bool(refpol), "permissions": bool(perm)}
    present_sh += [display_name[k] for k, v in extras_present.items() if v]
    missing_sh = [display_name[k] for k, v in essential_present.items() if not v]
    missing_sh += [display_name[k] for k, v in extras_present.items() if not v]

    warnings_sh = []
    if csp_has_unsafe:
        warnings_sh.append("CSP contiene 'unsafe-inline'/'unsafe-eval' (cap en A).")

    strict_weights = sum(f.get("weight",1) for f in findings)
    strict_ok = sum(f.get("weight",1) for f in findings if f["status"]==OK)
    strict_warn = sum(f.get("weight",1)*0.5 for f in findings if f["status"]==WARN)
    strict_score_pct = round(100 * (strict_ok + strict_warn) / max(strict_weights,1), 1)
    strict_worst = FAIL if any(f["status"]==FAIL for f in findings) else (WARN if any(f["status"]==WARN) else OK)

    return (status, rh, findings, strict_score_pct, strict_worst,
            sh_grade, missing_sh, present_sh, warnings_sh, final_url)

# -------- smart runner --------
def try_request_smart(opener, url, method, base_headers, base_body, args):
    url = ensure_scheme(url)
    origin = args.origin or (url_host_origin(url) if method.upper()=="OPTIONS" else None)
    headers = dict(base_headers)

    if not args.no_browserish:
        for k, v in browserish_headers().items():
            add_if_absent_ci(headers, k, v)

    if args.basic:
        headers = encode_basic_if_needed(headers, args.basic)
    if args.bearer:
        headers = add_bearer_if_needed(headers, args.bearer)

    body = base_body
    if method.upper() in WRITE_METHODS and not base_body:
        body, headers = smart_oauth_body_if_needed(url, body, headers)
        if not body: body = "{}"
    headers = infer_content_type_if_needed(headers, body)

    client_hdr = parse_single_header(args.client_header) if args.client_header else None

    return analyze_headers(opener, url, method, headers, body, args.timeout,
                           origin, args.acr_method, args.acr_headers,
                           client_hdr, args.no_client_header)

def run_once(opener, url, method, headers, body, args):
    return try_request_smart(opener, url, method, headers, body, args)

# =======================
# Pretty helpers
# =======================
REM_SNIPPETS = {
    "Strict-Transport-Security": "Agregar 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' (HTTPS).",
    "X-Content-Type-Options": "Agregar 'X-Content-Type-Options: nosniff'.",
    "X-Frame-Options / CSP frame-ancestors": "Usar 'X-Frame-Options: DENY/SAMEORIGIN' o CSP 'frame-ancestors'.",
    "Content-Security-Policy": "Definir CSP sin 'unsafe-*' y con 'default-src' restrictivo.",
    "Referrer-Policy": "Usar 'no-referrer' o 'strict-origin-when-cross-origin'.",
    "Permissions-Policy": "Restringir features: ej. 'Permissions-Policy: camera=(), geolocation=()'."
}

def sep():
    return f"{Colors.GREY}{'-'*70}{Colors.RESET}"

def grade_color(g):
    if g in ("A+","A"): return Colors.GREEN
    if g in ("B","C"): return Colors.YELLOW
    return Colors.RED

def state_color(s):
    return Colors.GREEN if s=="OK" else Colors.RED

def print_missing_list(miss):
    if not miss:
        print(f"  {Colors.GREEN}Missing:{Colors.RESET} (ninguna)")
        return
    print(f"  {Colors.YELLOW}Missing ({len(miss)}):{Colors.RESET}")
    for h in miss:
        hint = REM_SNIPPETS.get(h, "")
        if hint:
            print(f"    - {h}: {hint}")
        else:
            print(f"    - {h}")

def print_present_list(present):
    if not present:
        return
    print(f"  {Colors.GREEN}Present ({len(present)}):{Colors.RESET} " + ", ".join(present))

def legend_clienthdr(headers, args):
    if args.no_client_header:
        return "off"
    if args.client_header:
        return "custom"
    if header_exists_ci(headers, "X-Client"):
        return "preset"
    return "auto"

# =======================
# Main
# =======================
def main():
    epilog = textwrap.dedent("""
    Ejemplos:
      headcheck.py https://api.acme.com/endpoint --success "2xx"
      headcheck.py https://api.acme.com/endpoint --success "200,202,204"
      headcheck.py https://api.acme.com/endpoint --success "2xx,302"
      headcheck.py https://api.acme.com/endpoint --success "201-204"
      headcheck.py --urls-file objetivos.txt --include-substr "/refunds" --debug
      headcheck.py https://api.acme.com/endpoint --no-client-header
      headcheck.py https://api.acme.com/endpoint --client-header "X-Env: QA"
    """).strip()

    p = argparse.ArgumentParser(
        description="Validador de cabeceras para APIs (perfil SH, salida mínima). Soporta lotes, presets y filtros inteligentes.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=epilog
    )
    # Objetivo(s)
    p.add_argument("url", nargs="?", help="URL objetivo (con o sin http(s)://). Opcional con --urls-file/--paths-file.")
    p.add_argument("--urls-file", help="Archivo con URLs (una por línea). Acepta hosts, URLs o paths.")
    p.add_argument("--paths-file", help="Archivo con paths (una por línea). Requiere --base-url.")
    p.add_argument("--base-url", help="Base para combinar con --paths-file (ej.: https://host).")

    # Filtros de objetivos
    p.add_argument("--include-substr", action="append", default=[], help="Mantiene solo targets que contengan este texto (case-insensitive). Repetible.")
    p.add_argument("--include-regex", action="append", default=[], help="Mantiene solo targets que hagan match con esta regex. Repetible.")

    # Perfiles / reporting
    p.add_argument("--profile", choices=["strict","sh"], default="sh",
                   help="Métrica: 'sh' (default) o 'strict'.")
    p.add_argument("--pass-grade", choices=["A+","A","B","C","D","E","F"], default="A",
                   help="Umbral de aprobación para profile=sh.")
    p.add_argument("--show-strict", action="store_true",
                   help="Muestra Security Score y hallazgos extendidos (modo estricto).")
    p.add_argument("--show-warnings", action="store_true",
                   help="Muestra warnings SH (p.ej., CSP 'unsafe-inline').")
    p.add_argument("--show-present", action="store_true",
                   help="Lista headers de seguridad presentes además de los faltantes.")
    p.add_argument("--no-grade", action="store_true",
                   help="Oculta Grade/Estado (deja solo Missing).")
    p.add_argument("--debug", action="store_true",
                   help="Muestra resumen de códigos suprimidos y detalles auxiliares.")

    # Métodos
    p.add_argument("--method", choices=ALL_METHODS, help="Método único (opcional).")
    p.add_argument("--methods", help="CSV de métodos a probar (por defecto TODOS).")

    # Request crafting
    p.add_argument("--data", help="Cuerpo de la petición (string).")
    p.add_argument("--data-file", help="Archivo con el cuerpo (prioritario).")
    p.add_argument("--content-type", help="Content-Type (p.ej., application/json).")
    p.add_argument("--header", action="append", help='Header extra "Nombre: Valor"', default=[])
    p.add_argument("--cookie", action="append", help='Cookie "nombre=valor"', default=[])

    p.add_argument("--no-browserish", action="store_true", help="Desactiva headers tipo navegador.")

    # Auth
    p.add_argument("--basic", help='Authorization: Basic base64(user:pass). Ej: "id:secret"')
    p.add_argument("--bearer", help='Authorization: Bearer <TOKEN>')

    # TLS / red
    p.add_argument("--timeout", type=int, default=15, help="Timeout (s).")
    p.add_argument("--insecure", action="store_true", help="No verificar TLS/hostname (DEV/Burp).")
    p.add_argument("--proxy", help='Proxy Burp/ZAP. Ej: "http://127.0.0.1:8080"')

    # CORS
    p.add_argument("--origin", help="Origin para preflight (OPTIONS).")
    p.add_argument("--acr-method", help="Access-Control-Request-Method.")
    p.add_argument("--acr-headers", help="Access-Control-Request-Headers (csv).")

    # Salida / presets / Accept
    p.add_argument("--json", action="store_true", help="Salida JSON.")
    p.add_argument("--no-ok", action="store_true", help="Oculta hallazgos OK (solo --show-strict).")
    p.add_argument("--min-score", type=float, default=None, help="(strict) Exige score mínimo.")
    p.add_argument("--show-all", action="store_true", help="Incluye métodos que NO estén en el set de éxito (--success).")
    p.add_argument("--success", default="2xx",
                   help='Códigos considerados “éxito”. Ej: "2xx" (default) | "200,202,204" | "2xx,3xx" | "201-204".')
    p.add_argument("--accept", help="Forzar header Accept (default: application/json).")
    p.add_argument("--accept-any", action="store_true", help="Usar Accept: */* en lugar de JSON.")
    p.add_argument("--headers-file", action="append", default=[], help="Archivo con headers (JSON o líneas 'Nombre: Valor' / 'Nombre=Valor'). Repetible.")
    p.add_argument("--preset-kv", action="append", default=[], help="Headers inline 'k=v,k2=v2'. Repetible.")
    p.add_argument("--preset-override", action="store_true", help="Permite que los presets reemplacen headers existentes.")

    # Client header control
    p.add_argument("--no-client-header", action="store_true",
                   help="No enviar header de identificación por defecto.")
    p.add_argument("--client-header", default=None,
                   help='Header de identificación personalizado, ej.: "X-Client: MiTool" o "X-Env=QA".')

    args = p.parse_args()
    enable_win_ansi()

    # --- Construir lista de objetivos ---
    targets = []

    if args.urls_file:
        try:
            targets += read_lines_file(args.urls_file)
        except Exception as e:
            print(f"[!] No se pudo leer --urls-file: {e}", file=sys.stderr); sys.exit(2)

    if args.paths_file:
        if not args.base_url:
            print("[!] --paths-file requiere --base-url", file=sys.stderr); sys.exit(2)
        try:
            paths = read_lines_file(args.paths_file)
            for pth in paths:
                targets.append(join_base_and_path(args.base_url, pth))
        except Exception as e:
            print(f"[!] No se pudo leer --paths-file: {e}", file=sys.stderr); sys.exit(2)

    if args.url:
        targets.append(args.url)

    if not targets:
        print("[!] Debes indicar una URL o usar --urls-file / --paths-file + --base-url", file=sys.stderr)
        sys.exit(2)

    # Normaliza, deduplica y preserva orden
    seen = set()
    normalized_targets = []
    for t in targets:
        nt = t.strip()
        if not nt: continue
        if nt.startswith("/"):
            nt = nt.lstrip("/")
        if nt not in seen:
            seen.add(nt)
            normalized_targets.append(nt)

    # Filtros
    normalized_targets = filter_targets(normalized_targets, args.include_substr, args.include_regex)
    if not normalized_targets:
        print("[!] Después de aplicar filtros no quedaron objetivos para analizar.", file=sys.stderr)
        sys.exit(2)

    # --- Headers base ---
    headers = {}
    if args.headers_file:
        combined = {}
        for path in args.headers_file:
            combined.update(load_headers_file(path))
        apply_headers(headers, combined, override=args.preset_override)

    inline = parse_kv_inline_list(args.preset_kv)
    apply_headers(headers, inline, override=args.preset_override)

    cli_headers = parse_kv_colon(args.header)
    apply_headers(headers, cli_headers, override=True)

    if args.accept:
        set_header_ci(headers, "Accept", args.accept)
    elif args.accept_any:
        set_header_ci(headers, "Accept", "*/*")
    else:
        add_if_absent_ci(headers, "Accept", "application/json")

    if args.content_type: set_header_ci(headers, "Content-Type", args.content_type)
    if args.cookie: set_header_ci(headers, "Cookie", "; ".join(args.cookie))

    # Body
    body = ""
    if args.data_file:
        try:
            with open(args.data_file, "rb") as f:
                body = f.read().decode("utf-8", "ignore")
        except Exception as e:
            print(f"[!] No se pudo leer --data-file: {e}", file=sys.stderr); sys.exit(2)
    elif args.data:
        body = args.data

    # Métodos
    if args.methods:
        methods = [m.strip().upper() for m in args.methods.split(",") if m.strip()]
    elif args.method:
        methods = [args.method.upper()]
    else:
        methods = list(ALL_METHODS)

    opener = make_opener(verify_tls=not args.insecure, proxy_url=args.proxy)

    # Success predicate
    success_pred, success_label = build_success_pred(args.success)

    # ==== Ejecución por objetivo ====
    all_json_results = []
    worst_exit_code = 0

    for tgt in normalized_targets:
        results, suppressed = [], []
        final_urls = set()
        suppressed_counter = collections.Counter()

        for m in methods:
            b = body if m in WRITE_METHODS else ""
            try:
                (status, resp_headers, findings, strict_score_pct, strict_worst,
                 sh_grade, missing_sh, present_sh, warnings_sh, final_url) = run_once(
                    opener, tgt, headers=headers, method=m, body=b, args=args
                )
            except SystemExit as e:
                suppressed.append({"method": m, "reason": str(e)})
                suppressed_counter["exception"] += 1
                continue

            entry = {
                "method": m,
                "status_code": status,
                "strict_score_pct": strict_score_pct,
                "strict_worst": strict_worst,
                "sh_grade": sh_grade,
                "response_headers": resp_headers,
                "findings": findings,
                "missing_sh": missing_sh,
                "present_sh": present_sh,
                "warnings_sh": warnings_sh,
                "final_url": final_url,
            }

            if success_pred(status) or args.show_all:
                results.append(entry)
                final_urls.add(final_url)
            else:
                suppressed.append({"method": m, "reason": f"HTTP {status}", "final_url": final_url})
                suppressed_counter[str(status)] += 1

        # JSON
        if args.json:
            all_json_results.append({
                "url": ensure_scheme(tgt),
                "results": results,
                "suppressed": suppressed if args.show_all else None,
                "profile": args.profile,
                "pass_grade": args.pass_grade,
                "final_urls": sorted(final_urls)
            })
            order = {"A+":7,"A":6,"B":5,"C":4,"D":3,"E":2,"F":1}
            exit_code = 0
            for r in results:
                if args.profile == "sh":
                    if order[r["sh_grade"]] < order[args.pass_grade]:
                        exit_code = max(exit_code, 2)
                else:
                    if r["strict_worst"] == "FAIL": exit_code = 2
                    elif exit_code < 2 and r["strict_worst"] == "WARN": exit_code = 1
                    if args.min_score is not None and r["strict_score_pct"] < args.min_score:
                        exit_code = max(exit_code, 1)
            worst_exit_code = max(worst_exit_code, exit_code)
            continue

        # Pretty output
        start_url = ensure_scheme(tgt)
        print(f"\n{Colors.BOLD}{Colors.CYAN}Target:{Colors.RESET} {start_url}")
        if final_urls and (len(final_urls) > 1 or (list(final_urls)[0] != start_url)):
            finals = ", ".join(sorted(final_urls))
            print(f"{Colors.GREY}Final URL(s) after redirects:{Colors.RESET} {finals}")
        print(f"{Colors.GREY}Legend: Missing por método HTTP {success_label} "
              f"| browserish={'on' if not args.no_browserish else 'off'} "
              f"| Accept={get_header(headers,'Accept')} "
              f"| clientHdr={legend_clienthdr(headers, args)}{Colors.RESET}")
        print(sep())

        if not results:
            print(f"{Colors.YELLOW}No hubo respuestas HTTP {success_label} con los métodos probados.{Colors.RESET}")
            if args.debug and suppressed_counter:
                top = ", ".join([f"{k}×{v}" for k, v in suppressed_counter.most_common()])
                print(f"{Colors.GREY}Suprimidos (resumen):{Colors.RESET} {top or '(ninguno)'}")
            if suppressed and not args.show_all:
                print(f"{Colors.GREY}(Usa --show-all para ver métodos suprimidos y razones){Colors.RESET}")
            print(sep())
            worst_exit_code = max(worst_exit_code, 2)
            continue

        order = {"A+":7,"A":6,"B":5,"C":4,"D":3,"E":2,"F":1}
        exit_code = 0

        for r in results:
            passed = order[r["sh_grade"]] >= order[args.pass_grade]
            estado = "OK" if passed else "FAIL"
            col_state = state_color(estado)
            miss_count = len(r["missing_sh"])
            if args.no_grade:
                head_line = (f"[{r['method']}]  HTTP {r['status_code']}  |  "
                             f"Estado: {col_state}{estado}{Colors.RESET}  |  Missing({miss_count})")
            else:
                head_line = (f"[{r['method']}]  HTTP {r['status_code']}  |  "
                             f"Grade(SH): {grade_color(r['sh_grade'])}{r['sh_grade']}{Colors.RESET}  |  "
                             f"Estado: {col_state}{estado}{Colors.RESET}  |  Missing({miss_count})")
            print(head_line)
            if args.show_present:
                print_present_list(r["present_sh"])
            print_missing_list(r["missing_sh"])
            if args.show_warnings and r["warnings_sh"]:
                for w in r["warnings_sh"]:
                    print(f"  {Colors.GREY}Warning:{Colors.RESET} {w}")
            if args.profile == "strict" or args.show_strict:
                print(f"  {Colors.GREY}Security Score (strict): {r['strict_score_pct']}% — Worst: {r['strict_worst']}{Colors.RESET}")
            print()
            if not passed:
                exit_code = max(exit_code, 2)

        # Resumen tabular
        print(f"{Colors.BOLD}=== Resumen (HTTP {success_label}{', + no-éxito' if args.show_all else ''}) ==={Colors.RESET}")
        print(f"{'METHOD':7s} | {'HTTP':4s} | {'GRADE':5s} | {'ESTADO':6s} | MISSING")
        print("-"*60)
        for r in results:
            passed = order[r["sh_grade"]] >= order[args.pass_grade]
            estado = "OK" if passed else "FAIL"
            grade = r['sh_grade'] if not args.no_grade else "-"
            miss = ", ".join(r["missing_sh"]) if r["missing_sh"] else "(ninguno)"
            print(f"{r['method']:7s} | {str(r['status_code']):4s} | {grade:5s} | {estado:6s} | {miss}")

        if args.show_all and suppressed:
            for s in suppressed:
                print(f"{s['method']:7s} | {'-':4s} | {'-':5s} | {'SUPR.':6s} | {s.get('reason','')}")

        print(sep())
        worst_exit_code = max(worst_exit_code, exit_code)

    # JSON (multi-objetivo)
    if args.json:
        print(json.dumps(all_json_results, ensure_ascii=False, indent=2))
        sys.exit(worst_exit_code)

    sys.exit(worst_exit_code)

if __name__ == "__main__":
    main()
