#!/usr/bin/env python3
"""MYNEWJOB — backend v2 (stdlib uniquement).

Routes :
  GET  /                     → index.html (et autres pages statiques du site)
  GET  /api/health           → état + versions
  GET  /api/search?q&city    → offres (France Travail/LBA si clés, sinon jeu de test)
  GET  /api/score?text=      → score de compatibilité vs profil
  POST /api/letter           → lettre de motivation (DeepSeek) {title, company, details}
  POST /api/register         → {email, password}
  POST /api/login            → {email, password} → {token}
  GET  /api/me               → profil (Bearer token)
  POST /api/follow           → {title, company, city, text} (Bearer token)
  POST /api/unfollow         → {offer_id} (Bearer token)
  GET  /api/follows          → liste des candidatures suivies (Bearer token)

Clés (variables d'environnement) :
  FRANCETRAVAIL_ID / FRANCETRAVAIL_SECRET   API France Travail (gratuit, api.francetravail.io)
  LBA_API_TOKEN                            API La Bonne Alternance (gratuit, api.apprentissage.beta.gouv.fr)
  DEEPSEEK_API_KEY                         clé DeepSeek (lettres)

Lancement : python3 app.py [port]  (défaut 8000). DB créée à côté : mynewjob.db
"""
import json, os, re, secrets, sqlite3, sys, unicodedata, urllib.parse, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from hashlib import pbkdf2_hmac
from pathlib import Path

STATIC_DIR = Path(__file__).resolve().parent.parent   # sert le site (jobpilot/)
DB_PATH = Path(__file__).resolve().parent / "mynewjob.db"

# ── Base de données ───────────────────────────────────────────────────────────
def db():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    c = db()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        salt TEXT NOT NULL,
        hash TEXT NOT NULL,
        created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS tokens (
        token TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id),
        created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS follows (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(id),
        offer_key TEXT NOT NULL,
        title TEXT NOT NULL,
        company TEXT DEFAULT '',
        city TEXT DEFAULT '',
        status TEXT DEFAULT 'suivie',
        created_at TEXT DEFAULT (datetime('now')),
        UNIQUE(user_id, offer_key)
    );
    """)
    c.commit(); c.close()

def hash_pw(pw, salt=None):
    salt = salt or secrets.token_hex(16)
    h = pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 120_000).hex()
    return salt, h

# ── Profil (moteur de scoring) ───────────────────────────────────────────────
PROFILE = {
    "titre": "Analyste Cybersécurité — SOC & Détection",
    "points_forts": ["wazuh", "suricata", "siem", "xdr", "soar", "soc", "detection", "détection",
                     "incident response", "réponse à incident", "python", "powershell", "bash",
                     "active directory", "gpo", "nis2", "conformité", "audit", "llm", "ollama",
                     "azure", "aws", "linux", "windows server", "zabbix", "surveillance",
                     "supervision", "blue team", "cve", "logs", "automatisation", "shuffle",
                     "forensique", "glpi", "rgpd", "ebios", "sécurité", "cybersécurité"],
    "a_renforcer": ["splunk", "sentinel", "qradar", "sekoia", "elk", "elastic", "kql",
                    "hunting", "threat intelligence", "osint", "red team", "k8s", "kubernetes",
                    "terraform", "ci/cd", "devsecops"],
}

def normalize(t):
    t = (t or "").lower()
    t = unicodedata.normalize("NFD", t)
    return "".join(c for c in t if not unicodedata.combining(c))

def score_offer(text):
    t = normalize(text)
    hits = {kw for kw in PROFILE["points_forts"] if kw in t}
    head = normalize((text or "")[:400])
    head_hits = sum(1 for kw in hits if kw in head)
    score = min(99, int(len(hits) / len(PROFILE["points_forts"]) * 100 * 0.6
                       + (head_hits / max(4, len(hits)) * 100 * 0.4))) if hits else 0
    return {"score": score, "points_forts": sorted(hits)[:6],
            "a_renforcer": [kw for kw in PROFILE["a_renforcer"] if kw in t][:5],
            "keywords_trouves": len(hits), "total_keywords": len(PROFILE["points_forts"])}

# ── Jeu de test (recherche sans clé API) ─────────────────────────────────────
SAMPLE_OFFERS = [
    {"title": "Analyste SOC N1 (H/F)", "company": "UNIVOQ Partners", "city": "Paris",
     "text": "Qualification d'alertes XDR/EDR, analyse SIEM, réponse aux incidents, veille CTI. CDI 40-48k€, télétravail ponctuel."},
    {"title": "Expert cybersécurité pôle Détection SOC-DGA", "company": "Ministère des Armées", "city": "Arcueil",
     "text": "Supervision opérationnelle en temps court et réponse aux incidents sur les systèmes d'information. SOC, lutte informatique défensive, interface avec les équipes projets et prestataires. Débutant accepté, 2-3 ans SOC ou sortie d'école."},
    {"title": "Analyste SOC N2 XDR & Incident Response", "company": "STEEF", "city": "Paris",
     "text": "2-4 ans SOC/CERT, XDR, réponse à incidents, SIEM (Splunk, Sentinel). 42-65k€."},
    {"title": "Consultant Cybersécurité GRC", "company": "Phishia", "city": "Paris",
     "text": "NIS2, EBIOS RM, ISO 27001, gestion des risques, audits de conformité. 32-48k€."},
    {"title": "Ingénieur DevSecOps", "company": "TechCorp", "city": "Paris",
     "text": "CI/CD, Kubernetes, Terraform, SAST/DAST, pipelines sécurisés. 50-70k€."},
]

def search_offers(q, city=""):
    q = normalize(q)
    out = [o for o in SAMPLE_OFFERS if any(w in normalize(o["title"] + " " + o["text"] + " " + o["city"]) for w in q.split())] if q else []
    if city and city.lower() not in ("paris", ""):
        out = [o for o in out if city.lower() in o["city"].lower()]
    return out

# ── Fournisseurs de recherche réels (clés en env) ────────────────────────────
def search_francetravail(q, city=""):
    """API France Travail (OAuth2 client credentials)."""
    cid, sec = os.environ.get("FRANCETRAVAIL_ID", ""), os.environ.get("FRANCETRAVAIL_SECRET", "")
    if not cid or not sec:
        return None
    body = f"grant_type=client_credentials&client_id={cid}&client_secret={sec}&scope=api_offresdemploi_v2&realm=/partenaire".encode()
    req = urllib.request.Request("https://entreprise.pole-emploi.fr/connexion/oauth2/access_token?realm=/partenaire",
                                 data=body, headers={"Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=15) as r:
        tok = json.load(r)["access_token"]
    url = ("https://api.francetravail.io/partenaire/offresdemploi/v2/offres/search?"
           + urllib.parse.urlencode({"motsCles": q, "range": "0-9"}))
    req = urllib.request.Request(url, headers={"Authorization": "Bearer " + tok})
    with urllib.request.urlopen(req, timeout=15) as r:
        d = json.load(r)
    return [{"title": o.get("intitule", ""), "company": (o.get("entreprise") or {}).get("nom", ""),
             "city": (o.get("lieuTravail") or {}).get("libelle", ""),
             "text": (o.get("description") or "")[:500]} for o in d.get("resultats", [])]

def search_lba(q, city=""):
    token = os.environ.get("LBA_API_TOKEN", "")
    if not token:
        return None
    url = "https://api.apprentissage.beta.gouv.fr/api/v1/jobs/search?query=" + urllib.parse.quote(q)
    req = urllib.request.Request(url, headers={"Authorization": "Bearer " + token})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.load(r)

def search(q, city=""):
    for fn in (search_francetravail, search_lba):
        try:
            r = fn(q, city)
        except Exception:
            r = None
        if r is not None:
            return {"source": fn.__name__.replace("search_", ""), "offres": r}
    return {"source": "jeu de test (clés API absentes)", "offres": search_offers(q, city)}

# ── Lettre via DeepSeek ──────────────────────────────────────────────────────
def generate_letter(title, company, details=""):
  key = os.environ.get("DEEPSEEK_API_KEY", "")
  if not key:
      return {"lettre": template_letter(title, company, details), "mode": "gabarit"}
  profile = ("Analyste cybersécurité, 3 ans d'expérience SOC (Wazuh, Suricata, SOAR/Shuffle, "
             "LLM local Ollama, hardening Active Directory, conformité NIS2/ANSSI). "
             "Master Cybersécurité fin octobre 2026, CCNA, anglais C1.")
  sys_msg = ("Vous rédigez des lettres de motivation en français, concises et professionnelles. "
             "Maximum 180 mots, ton sobre. Terminez par la signature : Youssef Guerniou.")
  user_msg = (f"Poste : {title}\nEntreprise : {company}\n"
              + (f"Détails de l'offre : {details}\n" if details else "")
              + f"Profil du candidat : {profile}")
  body = json.dumps({"model": "deepseek-chat",
                     "messages": [{"role": "system", "content": sys_msg},
                                  {"role": "user", "content": user_msg}],
                     "temperature": 0.7, "max_tokens": 500}).encode()
  req = urllib.request.Request("https://api.deepseek.com/chat/completions", data=body,
                               headers={"Content-Type": "application/json", "Authorization": "Bearer " + key})
  with urllib.request.urlopen(req, timeout=60) as r:
      return {"lettre": json.load(r)["choices"][0]["message"]["content"], "mode": "ia"}

def template_letter(title, company, details=""):
  """Gabarit hors ligne : fonctionne sans aucune clé API."""
  desc = details[:300] if details else "le poste proposé"
  exp = ("Mon expérience de trois ans en supervision SOC (Wazuh, Suricata), en réponse aux "
         "incidents et en automatisation des analyses d'alertes me semble directement "
         "transposable à ce poste.")
  return (f"Madame, Monsieur,\n\n"
          f"Votre offre « {title} » retient toute mon attention. {exp}\n\n"
          f"J'ai notamment automatisé l'analyse d'un volume élevé d'alertes grâce à un LLM local, "
          f"une démarche qui rejoint les besoins décrits pour {desc}.\n\n"
          f"Disponible rapidement, je me tiens à votre disposition pour un entretien.\n\n"
          f"Cordialement,\nYoussef Guerniou")

# ── Serveur HTTP ─────────────────────────────────────────────────────────────
MIME = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
        ".js": "application/javascript", ".png": "image/png", ".jpg": "image/jpeg",
        ".svg": "image/svg+xml", ".ico": "image/x-icon"}

class Handler(BaseHTTPRequestHandler):
    def _json(self, obj, code=200):
        b = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _static(self, path):
        if path in ("/", ""):
            path = "/index.html"
        f = STATIC_DIR / path.lstrip("/")
        if not f.is_file() or f.suffix not in MIME:
            self._json({"error": "not found"}, 404)
            return
        b = f.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", MIME[f.suffix])
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _user(self):
        auth = self.headers.get("Authorization", "")
        tok = auth.replace("Bearer ", "").strip()
        c = db()
        row = c.execute("SELECT user_id FROM tokens WHERE token=?", (tok,)).fetchone()
        c.close()
        return row["user_id"] if row else None

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        p = urllib.parse.parse_qs(u.query)
        if u.path.startswith("/api/"):
            if u.path == "/api/health":
                self._json({"status": "ok", "profil": PROFILE["titre"], "users": True})
            elif u.path == "/api/search":
                self._json(search((p.get("q") or [""])[0], (p.get("city") or [""])[0]))
            elif u.path == "/api/score":
                self._json(score_offer((p.get("text") or [""])[0]))
            elif u.path == "/api/me":
                uid = self._user()
                self._json({"authentifie": uid is not None, "user_id": uid})
            elif u.path == "/api/follows":
                uid = self._user()
                if not uid:
                    self._json({"error": "authentification requise"}, 401)
                    return
                c = db()
                rows = c.execute("SELECT offer_key, title, company, city, status, created_at FROM follows WHERE user_id=? ORDER BY id DESC", (uid,)).fetchall()
                c.close()
                self._json({"candidatures": [dict(r) for r in rows]})
            else:
                self._json({"error": "route inconnue"}, 404)
        else:
            self._static(u.path)

    def do_POST(self):
        u = urllib.parse.urlparse(self.path)
        n = int(self.headers.get("Content-Length", 0))
        try:
            data = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            data = {}
        c = db()
        if u.path == "/api/register":
            email, pw = (data.get("email") or "").strip().lower(), data.get("password") or ""
            if not re.match(r"[^@]+@[^@]+\.[^@]+", email) or len(pw) < 8:
                self._json({"error": "email invalide ou mot de passe < 8 caractères"}, 400); return
            salt, h = hash_pw(pw)
            try:
                c.execute("INSERT INTO users (email, salt, hash) VALUES (?,?,?)", (email, salt, h))
                c.commit()
            except sqlite3.IntegrityError:
                self._json({"error": "email déjà utilisé"}, 409); return
            tok = secrets.token_hex(24)
            uid = c.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()["id"]
            c.execute("INSERT INTO tokens (token, user_id) VALUES (?,?)", (tok, uid)); c.commit()
            self._json({"token": tok, "user_id": uid})
        elif u.path == "/api/login":
            email, pw = (data.get("email") or "").strip().lower(), data.get("password") or ""
            row = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
            if not row or hash_pw(pw, row["salt"])[1] != row["hash"]:
                self._json({"error": "email ou mot de passe incorrect"}, 401); return
            tok = secrets.token_hex(24)
            c.execute("INSERT INTO tokens (token, user_id) VALUES (?,?)", (tok, row["id"])); c.commit()
            self._json({"token": tok, "user_id": row["id"]})
        elif u.path == "/api/follow":
            uid = self._user()
            if not uid:
                self._json({"error": "authentification requise"}, 401); return
            key = data.get("offer_key") or (data.get("title") or "").strip()
            if not key:
                self._json({"error": "offer_key requis"}, 400); return
            c.execute("INSERT OR IGNORE INTO follows (user_id, offer_key, title, company, city) VALUES (?,?,?,?,?)",
                      (uid, key, data.get("title", ""), data.get("company", ""), data.get("city", "")))
            c.commit()
            self._json({"ok": True})
        elif u.path == "/api/unfollow":
            uid = self._user()
            if not uid:
                self._json({"error": "authentification requise"}, 401); return
            c.execute("DELETE FROM follows WHERE user_id=? AND offer_key=?", (uid, data.get("offer_key", "")))
            c.commit()
            self._json({"ok": True})
        elif u.path == "/api/letter":
            self._json(generate_letter(data.get("title", ""), data.get("company", ""), data.get("details", "")))
        else:
            self._json({"error": "route inconnue"}, 404)
        c.close()

    def log_message(self, *a):
        pass

if __name__ == "__main__":
    init_db()
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    print(f"MYNEWJOB v2 sur http://localhost:{port} (site + API) — Ctrl+C pour arrêter")
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
