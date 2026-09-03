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
from base64 import b64decode, b64encode
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from hashlib import pbkdf2_hmac
from html import escape
from io import BytesIO
from pathlib import Path
import tempfile

try:
    from pypdf import PdfReader
    HAS_PYPDF = True
except ImportError:
    HAS_PYPDF = False

try:
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.lib.colors import HexColor
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False

STATIC_DIR = Path(__file__).resolve().parent.parent   # sert le site (jobpilot/)
DB_PATH = Path(__file__).resolve().parent / "mynewjob.db"

# ── Base de données ───────────────────────────────────────────────────────────
def db():
    c = sqlite3.connect(DB_PATH, timeout=15)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA busy_timeout=15000")
    return c

def init_db():
    c = db()
    c.execute("PRAGMA journal_mode=WAL")
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
    {"title": "Développeur Full-Stack JavaScript (H/F)", "company": "NovaSoft", "city": "Paris",
     "text": "React, Node.js, TypeScript, API REST, Git. CDI ou alternance, 38-52k€."},
    {"title": "Data Analyst Junior", "company": "Datacraft", "city": "Lyon",
     "text": "SQL, Python, Power BI, analyse de données, dashboards. Alternance acceptée, 35-45k€."},
    {"title": "Chargé de Marketing Digital", "company": "GlowMedia", "city": "Paris",
     "text": "SEO, SEA, réseaux sociaux, création de contenu, CRM. Stage ou alternance."},
    {"title": "Assistant Comptable (H/F)", "company": "FinadVis", "city": "Bordeaux",
     "text": "Comptabilité générale, gestion, facturation, trésorerie. Alternance acceptée."},
    {"title": "Chargé de Recrutement RH", "company": "PeopleFirst", "city": "Lille",
     "text": "Recrutement, paie, droit du travail, relations sociales. 32-40k€."},
    {"title": "Juriste Droit des Contrats", "company": "LexPartners", "city": "Paris",
     "text": "Rédaction de contrats, conformité, réglementation, compliance. CDI 40-55k€."},
    {"title": "UX/UI Designer", "company": "PixelLab", "city": "Remote",
     "text": "Figma, UX, UI, maquettes, design system, recherche utilisateur. Alternance."},
    {"title": "Technicien Systèmes & Réseaux", "company": "NetWork", "city": "Nantes",
     "text": "Linux, Windows Server, réseaux, virtualisation, support N2. 30-38k€."},
    {"title": "Commercial B2B (H/F)", "company": "Venteo", "city": "Paris",
     "text": "Prospection, négociation, relation client, développement de portefeuille. CDI 32-45k€ + variable."},
    {"title": "Business Developer", "company": "GrowthCo", "city": "Paris",
     "text": "Développement commercial, acquisition de clients, négociation, suivi CRM. 35-50k€."},
    {"title": "Conseiller de vente", "company": "RetailPro", "city": "Lyon",
     "text": "Vente, conseil client, merchandising, encaissement. CDD ou CDI."},
    {"title": "Infirmier diplômé d'État (H/F)", "company": "Clinique SantéPlus", "city": "Lyon",
     "text": "Soins infirmiers, prise en charge des patients, suivi médical. CDI temps plein."},
    {"title": "Aide-soignant", "company": "EHPAD Les Tilleuls", "city": "Marseille",
     "text": "Accompagnement des résidents, soins d'hygiène, assistance au quotidien."},
    {"title": "Professeur des écoles", "company": "Éducation Nationale", "city": "Créteil",
     "text": "Enseignement primaire, pédagogie, préparation des cours, évaluation des élèves."},
    {"title": "Formateur en informatique", "company": "FormaTech", "city": "Paris",
     "text": "Animation de formations, pédagogie, conception de supports, accompagnement des apprenants."},
    {"title": "Responsable logistique", "company": "LogiTrans", "city": "Lille",
     "text": "Gestion des flux, optimisation des entrepôts, supply chain, coordination des équipes."},
    {"title": "Chauffeur livreur", "company": "RapidDelivery", "city": "Nantes",
     "text": "Livraison de marchandises, tournée, gestion des documents de transport."},
    {"title": "Technicien de maintenance industrielle", "company": "IndusPro", "city": "Lyon",
     "text": "Maintenance préventive et curative, automatisme, production industrielle."},
    {"title": "Opérateur de production", "company": "FabriCo", "city": "Mulhouse",
     "text": "Conduite de ligne de production, contrôle qualité, respect des cadences."},
    {"title": "Chef de chantier BTP", "company": "ConstruCorp", "city": "Bordeaux",
     "text": "Conduite de travaux, coordination du chantier, gros œuvre, second œuvre."},
    {"title": "Électricien bâtiment", "company": "ElecBat", "city": "Toulouse",
     "text": "Installation électrique, mise aux normes, dépannage, chantier."},
    {"title": "Cuisinier (H/F)", "company": "Restaurant Le Gourmet", "city": "Paris",
     "text": "Préparation des plats, cuisine, respect des normes HACCP, service en salle."},
    {"title": "Réceptionniste d'hôtel", "company": "Hôtel Azur", "city": "Nice",
     "text": "Accueil des clients, gestion des réservations, réception, hébergement."},
    {"title": "Assistant administratif (H/F)", "company": "AdmiCorp", "city": "Paris",
     "text": "Gestion administrative, secrétariat, classement, rédaction de courriers."},
    {"title": "Secrétaire de direction", "company": "Cabinet Conseil", "city": "Lyon",
     "text": "Assistanat de direction, gestion d'agenda, comptes rendus, organisation."},
    {"title": "Éducateur spécialisé", "company": "Association Horizon", "city": "Marseille",
     "text": "Accompagnement social, insertion, suivi individualisé des publics en difficulté."},
    {"title": "Auxiliaire de vie", "company": "Aide & Service", "city": "Rennes",
     "text": "Aide à domicile, accompagnement des personnes âgées, services à la personne."},
    {"title": "Ingénieur R&D", "company": "InnovaLabs", "city": "Grenoble",
     "text": "Recherche et développement, prototypage, innovation technologique."},
    {"title": "Chercheur en sciences des données", "company": "CNRS", "city": "Saclay",
     "text": "Recherche scientifique, publication, analyse de données, R&D."},
    {"title": "Monteur vidéo", "company": "StudioProd", "city": "Paris",
     "text": "Montage vidéo, post-production, audiovisuel, création de contenus."},
    {"title": "Journaliste", "company": "MediaNews", "city": "Paris",
     "text": "Rédaction d'articles, reportage, investigation, culture de l'information."},
    {"title": "Chargé de mission environnement", "company": "EcoConseil", "city": "Nantes",
     "text": "Développement durable, gestion environnementale, QHSE, écologie."},
    {"title": "Ingénieur QHSE", "company": "GreenIndustry", "city": "Lyon",
     "text": "Qualité, hygiène, sécurité, environnement, conformité réglementaire."},
    {"title": "Négociateur immobilier", "company": "ImmoReal", "city": "Paris",
     "text": "Transaction immobilière, estimation, prospection, gestion locative."},
    {"title": "Gestionnaire de copropriété", "company": "SyndicPro", "city": "Lyon",
     "text": "Gestion locative, copropriété, assemblées générales, immobilier."},
    {"title": "Technicien télécom", "company": "TelNet", "city": "Rennes",
     "text": "Installation fibre optique, réseaux télécom, maintenance des équipements."},
    {"title": "Acheteur (H/F)", "company": "AchatGroup", "city": "Paris",
     "text": "Achats, négociation fournisseurs, approvisionnement, sourcing."},
    {"title": "Coach sportif", "company": "FitClub", "city": "Paris",
     "text": "Encadrement sportif, préparation physique, cours collectifs, fitness."},
    {"title": "Agent de sécurité", "company": "SecuriGard", "city": "Paris",
     "text": "Surveillance, gardiennage, contrôle d'accès, sécurité incendie, prévention."},
    {"title": "Conseiller bancaire", "company": "Banque Nationale", "city": "Paris",
     "text": "Conseil clientèle, produits bancaires, assurance, gestion de portefeuille."},
    {"title": "Chargé d'assurance", "company": "AssurPlus", "city": "Lyon",
     "text": "Assurance, souscription, gestion des sinistres, relation client."},
]

# Mots-clés par domaine (pour le feed « selon ton CV »)
DOMAIN_KEYWORDS = {
    "cybersecurite": ["cyber", "sécurité", "securite", "siem", "soc", "xdr", "edr", "incident", "nis2",
                      "pentest", "wazuh", "suricata", "forensique", "threat", "cve", "firewall", "ids", "ips",
                      "audit", "hacking", "ransomware", "vulnérabilité"],
    "informatique": ["développeur", "developpeur", "développement", "python", "java", "javascript", "react",
                     "node", "typescript", "docker", "kubernetes", "terraform", "git", "devops", "api",
                     "cloud", "aws", "azure", "linux", "réseaux", "reseaux", "full-stack", "fullstack"],
    "data": ["data", "sql", "pandas", "power bi", "machine learning", "analyse de données", "analyse de donnees",
             "dashboards", "statistique", "big data"],
    "marketing": ["marketing", "seo", "sea", "réseaux sociaux", "reseaux sociaux", "contenu", "crm", "publicité", "marque"],
    "finance": ["comptable", "comptabilité", "comptabilite", "trésorerie", "tresorerie", "facturation", "audit financier",
                "expert-comptable", "fiscalité", "fiscalite", "contrôle de gestion", "controle de gestion", "finance"],
    "banque_assurance": ["banque", "bancaire", "assurance", "courtage", "crédit", "credit", "souscription",
                         "sinistre", "conseiller financier", "gestion de patrimoine"],
    "rh": ["recrutement", "paie", "droit du travail", "ressources humaines", "relations sociales"],
    "droit": ["droit", "juriste", "contrat", "réglementation", "reglementation", "compliance"],
    "design": ["design", "figma", "ux", "ui", "maquette", "graphisme", "design system"],
    "vente": ["vente", "ventes", "commercial", "commerciale", "commerce", "négociation", "negociation",
              "prospection", "relation client", "business developer", "account manager",
              "conseiller de vente", "retail", "distribution", "business development"],
    "sante": ["infirmier", "infirmière", "infirmiere", "medecin", "médecin", "santé", "sante", "soins",
              "aide-soignant", "medical", "médical", "pharmacien", "kinésithérapeute", "kinesitherapeute",
              "hôpital", "hopital", "clinic"],
    "education": ["enseignant", "enseignement", "professeur", "formation", "éducation", "education", "pédagogie",
                  "pedagogie", "formateur", "école", "ecole", "tuteur", "cours", "apprentissage"],
    "logistique": ["logistique", "transport", "entrepôt", "entrepot", "magasinier", "chauffeur", "livreur",
                   "supply chain", "cariste", "gestion de stock", "livraison"],
    "industrie": ["production", "maintenance", "industrie", "opérateur", "operateur", "usine", "fabrication",
                  "automatisme", "chaîne de production", "chaine de production", "ligne de production"],
    "btp": ["btp", "construction", "bâtiment", "batiment", "chantier", "maçon", "macon", "électricien",
            "electricien", "plombier", "génie civil", "genie civil", "conduite de travaux"],
    "hotel_restauration": ["restauration", "cuisine", "cuisinier", "hôtel", "hotel", "tourisme", "serveur",
                           "réceptionniste", "receptionniste", "hébergement", "hebergement", "service en salle", "haccp"],
    "administration": ["assistant", "assistante", "administratif", "secrétariat", "secretariat", "secrétaire",
                       "secretaire", "gestion administrative", "accueil", "back office", "assistanat"],
    "social": ["éducateur", "educateur", "aide à domicile", "aide a domicile", "services à la personne",
               "services a la personne", "travailleur social", "accompagnement social", "animateur",
               "insertion", "auxiliaire de vie"],
    "recherche": ["recherche", "r&d", "recherche et développement", "recherche et developpement", "scientifique",
                  "chercheur", "prototypage", "publication", "innovation", "laboratoire"],
    "audiovisuel": ["audiovisuel", "vidéo", "video", "montage", "journalisme", "journaliste", "rédaction",
                    "redaction", "reportage", "investigation", "article", "post-production", "post production",
                    "réalisation", "realisation", "média", "media"],
    "environnement": ["environnement", "écologie", "ecologie", "développement durable", "developpement durable",
                      "qhse", "hse", "gestion environnementale", "rse", "biodiversité", "biodiversite",
                      "santé au travail", "sante au travail"],
    "immobilier": ["immobilier", "transaction immobilière", "transaction immobiliere", "copropriété", "copropriete",
                   "gestion locative", "estimation", "négociateur immobilier", "negociateur immobilier", "syndic"],
    "telecom": ["télécom", "telecom", "télécommunications", "telecommunications", "fibre optique", "réseaux télécom",
                "reseaux télécom", "opérateur télécom", "operateur telecom"],
    "achats": ["achats", "acheteur", "approvisionnement", "sourcing", "négociation fournisseurs",
               "negociation fournisseurs", "supply", "fournisseurs"],
    "sport": ["sport", "coach sportif", "préparation physique", "preparation physique", "fitness",
              "encadrement sportif", "éducateur sportif", "educateur sportif"],
    "securite_privee": ["agent de sécurité", "agent de securite", "gardiennage", "surveillance", "contrôle d'accès",
                        "controle d'acces", "sécurité incendie", "securite incendie", "prévention", "prevention"],
}

# Synonymes et abréviations saisis naturellement par les candidats.
DOMAIN_ALIASES = {
    "cybersecurite": ["cyber", "cybersec", "cybersecurite", "securite informatique", "secops", "blue team", "soc"],
    "informatique": ["informatique", "it", "dev", "developpement", "programmation", "logiciel", "software",
                     "systeme", "systemes et reseaux", "admin systeme", "support informatique", "devops", "cloud"],
    "data": ["data", "donnees", "analyse de donnees", "data science", "business intelligence", "bi"],
    "marketing": ["marketing", "communication", "communication digitale", "digital", "seo", "sea"],
    "finance": ["finance", "compta", "comptabilite", "controle de gestion", "audit financier", "fiscalite"],
    "banque_assurance": ["banque", "assurance", "bancaire", "courtage", "assurances"],
    "rh": ["rh", "ressources humaines", "recrutement", "talent acquisition", "paie"],
    "droit": ["droit", "juridique", "juriste", "legal", "compliance"],
    "design": ["design", "graphisme", "ux", "ui", "ux ui", "product design", "figma"],
    "vente": ["vente", "ventes", "commercial", "commerce", "sales", "bizdev", "business dev",
              "business developer", "account manager", "distribution"],
    "sante": ["sante", "santé", "soins", "infirmier", "medical", "médical", "hôpital", "hopital", "médecine", "medecine"],
    "education": ["education", "éducation", "enseignement", "enseignant", "professeur", "formation", "formateur", "école", "ecole"],
    "logistique": ["logistique", "transport", "entrepôt", "entrepot", "magasinier", "chauffeur", "livreur", "supply chain"],
    "industrie": ["industrie", "production", "maintenance", "opérateur", "operateur", "usine", "fabrication"],
    "btp": ["btp", "construction", "bâtiment", "batiment", "chantier", "génie civil", "genie civil"],
    "hotel_restauration": ["restauration", "hotel", "hôtel", "cuisine", "cuisinier", "tourisme", "serveur"],
    "administration": ["administratif", "administration", "assistant", "assistante", "secrétariat", "secretariat", "secretaire", "assistanat"],
    "social": ["social", "éducateur", "educateur", "aide a domicile", "services a la personne", "travail social", "animateur"],
    "recherche": ["recherche", "r&d", "r et d", "scientifique", "chercheur", "laboratoire", "innovation"],
    "audiovisuel": ["audiovisuel", "video", "vidéo", "montage", "journalisme", "journaliste", "média", "media"],
    "environnement": ["environnement", "écologie", "ecologie", "développement durable", "developpement durable", "qhse", "rse"],
    "immobilier": ["immobilier", "transaction immobilière", "transaction immobiliere", "copropriété", "copropriete", "gestion locative"],
    "telecom": ["telecom", "télécom", "télécommunications", "telecommunications", "fibre", "fibre optique"],
    "achats": ["achats", "acheteur", "approvisionnement", "sourcing", "supply chain"],
    "sport": ["sport", "coach sportif", "fitness", "éducateur sportif", "educateur sportif", "préparation physique"],
    "securite_privee": ["agent de securite", "agent de sécurité", "gardiennage", "sécurité privée", "securite privee", "surveillance"],
}

DOMAIN_LABELS = {
    "cybersecurite": "cybersécurité",
    "informatique": "informatique",
    "data": "data analyse de données",
    "marketing": "marketing communication digitale",
    "finance": "finance comptabilité",
    "banque_assurance": "banque assurance",
    "rh": "ressources humaines",
    "droit": "droit juridique",
    "design": "design UX UI",
    "vente": "vente commerce commercial",
    "sante": "santé soins médical",
    "education": "éducation enseignement formation",
    "logistique": "logistique transport",
    "industrie": "industrie production maintenance",
    "btp": "bâtiment travaux construction",
    "hotel_restauration": "hôtellerie restauration tourisme",
    "administration": "administratif secrétariat",
    "social": "social services à la personne",
    "recherche": "recherche R&D scientifique",
    "audiovisuel": "audiovisuel médias journalisme",
    "environnement": "environnement développement durable",
    "immobilier": "immobilier transaction gestion locative",
    "telecom": "télécoms télécommunications",
    "achats": "achats approvisionnement",
    "sport": "sport encadrement sportif",
    "securite_privee": "sécurité privée surveillance gardiennage",
}

def kw_match(text, kw):
    """Mot-clé avec frontières de mot pour les termes courts (évite « soc » dans « sociales »)."""
    kw = normalize(kw)
    if len(kw) <= 4:
        return re.search(r"(?<![a-z0-9])" + re.escape(kw) + r"(?![a-z0-9])", text) is not None
    return kw in text

def detect_domain(text):
    t = normalize(text)
    best, best_n = None, 0
    for dom, kws in DOMAIN_KEYWORDS.items():
        aliases = DOMAIN_ALIASES.get(dom, [])
        n = sum(1 for kw in [*aliases, *kws] if kw_match(t, kw))
        if n > best_n:
            best, best_n = dom, n
    return best or "informatique", best_n

def canonical_search_query(q):
    """Traduit une saisie courante vers un libellé compris par les moteurs d'offres."""
    dom, confidence = detect_domain(q)
    return DOMAIN_LABELS[dom] if confidence else (q or "").strip()

def extract_skills(text):
    t = normalize(text)
    found = []
    for dom, kws in DOMAIN_KEYWORDS.items():
        for kw in kws:
            if kw_match(t, kw) and normalize(kw) not in [normalize(x) for x in found]:
                found.append(kw)
    # limite l'affichage, dédoublonne les quasi-synonymes
    return found[:12]

def analyze_ats(text, domain):
    """Évalue la lisibilité ATS et propose uniquement des mots-clés à valider."""
    t = normalize(text)
    unique = []
    for kw in DOMAIN_KEYWORDS.get(domain, []):
        if normalize(kw) not in [normalize(x) for x in unique]:
            unique.append(kw)
    present = [kw for kw in unique if kw_match(t, kw)]
    missing = [kw for kw in unique if not kw_match(t, kw)][:8]
    section_checks = ("experience", "formation", "competence")
    structure_points = sum(10 for heading in section_checks if heading in t)
    contact_points = 10 if re.search(r"[\w.+-]+@[\w.-]+\.[a-z]{2,}", t) else 0
    keyword_points = round(60 * len(present) / max(1, len(unique)))
    return {
        "score": min(100, keyword_points + structure_points + contact_points),
        "mots_cles_presents": present[:10],
        "mots_cles_a_valider": missing,
        "conseil": "Ajoutez uniquement les mots-clés correspondant réellement à votre expérience.",
    }

def feed_offers(q, domain=None):
    """Offres du domaine, notées et triées (moteur du swipe)."""
    tq = normalize(q)
    dom = domain or detect_domain(tq)[0]
    kws = DOMAIN_KEYWORDS.get(dom, [])
    out = []
    for o in SAMPLE_OFFERS:
        blob = normalize(o["title"] + " " + o["text"])
        if kws and not any(kw_match(blob, k) for k in kws):
            continue
        s = score_offer(o["text"] + " " + o["title"])
        out.append({**o, "score": s["score"], "points_forts": s["points_forts"]})
    out.sort(key=lambda x: -x["score"])
    return {"domaine": dom, "offres": out[:10]}

def search_offers(q, city=""):
    qn = normalize(q)
    dom, confidence = detect_domain(qn)
    if qn and confidence:
        out = [o for o in SAMPLE_OFFERS
               if detect_domain(o["title"] + " " + o["text"])[0] == dom]
    else:
        out = [o for o in SAMPLE_OFFERS
               if qn and any(w in normalize(o["title"] + " " + o["text"] + " " + o["city"])
                             for w in qn.split())]
    cityn = normalize(city)
    if cityn:
        out = [o for o in out if cityn in normalize(o["city"])]
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
    provider_q = canonical_search_query(q)
    for fn in (search_francetravail, search_lba):
        try:
            r = fn(provider_q, city)
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

def extract_pdf_text(pdf_b64):
    if not HAS_PYPDF:
        raise RuntimeError("pypdf absent")
    try:
        raw = b64decode(pdf_b64, validate=True)
        reader = PdfReader(BytesIO(raw))
        text = "\n".join((page.extract_text() or "") for page in reader.pages)
    except Exception as exc:
        raise ValueError(f"PDF illisible : {exc}") from exc
    if not text.strip():
        raise ValueError("Aucun texte extrait (CV scanné en image ?)")
    return text

def fallback_structure(source, keywords):
    """Structure minimale extraite du texte brut, sans rien inventer."""
    lines = [re.sub(r"\s+", " ", l).strip() for l in source.splitlines() if l.strip()]
    email = phone = ""
    for line in lines:
        m = re.search(r"[\w.+-]+@[\w.-]+\.[a-z]{2,}", line)
        if m and not email:
            email = m.group(0)
        m2 = re.search(r"\b0[67][ .-]?\d{2}(?:[ .-]?\d{2}){3}\b", line)
        if m2 and not phone:
            phone = m2.group(0)
    return {
        "nom": lines[0] if lines else "",
        "titre": "",
        "contact": {"email": email, "telephone": phone, "localisation": "", "github": "", "linkedin": ""},
        "profil": " ".join(lines[1:])[:1400],
        "competences": [{"groupe": "Compétences ciblées", "items": " · ".join(keywords)}] if keywords else [],
        "experiences": [], "formation": [], "certifications": [], "langues": [],
    }

def _coerce_struct(raw):
    if not isinstance(raw, dict):
        raise ValueError("JSON attendu")
    contact = raw.get("contact") if isinstance(raw.get("contact"), dict) else {}
    def s(v): return str(v).strip() if v else ""
    def lst(v): return [str(x).strip() for x in v] if isinstance(v, list) else []
    def groups(v):
        out = []
        for g in (v if isinstance(v, list) else []):
            if isinstance(g, dict):
                out.append({"groupe": s(g.get("groupe")), "items": s(g.get("items"))})
        return out
    def exps(v):
        out = []
        for e in (v if isinstance(v, list) else []):
            if isinstance(e, dict):
                out.append({"role": s(e.get("role")), "meta": s(e.get("meta")), "bullets": lst(e.get("bullets"))})
        return out
    def entries(v):
        out = []
        for e in (v if isinstance(v, list) else []):
            if isinstance(e, dict):
                out.append({"role": s(e.get("role")), "meta": s(e.get("meta"))})
            elif isinstance(e, str):
                out.append({"role": e.strip(), "meta": ""})
        return out
    return {
        "nom": s(raw.get("nom")), "titre": s(raw.get("titre")),
        "contact": {k: s(contact.get(k)) for k in ("email", "telephone", "localisation", "github", "linkedin")},
        "profil": s(raw.get("profil")), "competences": groups(raw.get("competences")),
        "experiences": exps(raw.get("experiences")), "formation": entries(raw.get("formation")),
        "certifications": lst(raw.get("certifications")), "langues": lst(raw.get("langues")),
    }

def rewrite_cv_with_ai(source, keywords, target=""):
    key = os.environ.get("DEEPSEEK_API_KEY", "")
    if not key:
        return fallback_structure(source, keywords), "mise en page ATS"
    system = (
        "Vous extrayez et reformulez un CV en français, sans rien inventer. Vous recevez le texte brut d'un "
        "CV PDF. Conservez strictement les faits : identité, coordonnées, employeurs, dates, diplômes et "
        "compétences réellement mentionnés. N'inventez jamais une compétence, une mission, un chiffre ou un "
        "diplôme. Reformulez le profil et les missions de façon concise et professionnelle. Intégrez les "
        "mots-clés validés uniquement lorsqu'ils sont cohérents avec les faits. Répondez UNIQUEMENT en JSON "
        "valide, sans texte autour, avec ce schéma exact : "
        '{"nom":"","titre":"","contact":{"email":"","telephone":"","localisation":"","github":"","linkedin":""},'
        '"profil":"","competences":[{"groupe":"","items":""}],'
        '"experiences":[{"role":"","meta":"","bullets":[""]}],'
        '"formation":[{"role":"","meta":""}],"certifications":[""],"langues":[""]}. '
        "Champ absent : chaîne vide ou liste vide."
    )
    user = (f"Métier ciblé : {target or 'domaine détecté'}\n"
            f"Mots-clés validés par le candidat : {', '.join(keywords)}\n\nTexte brut du CV :\n{source[:18000]}")
    body = json.dumps({"model": "deepseek-chat", "messages": [
        {"role": "system", "content": system}, {"role": "user", "content": user}],
        "temperature": 0.1, "max_tokens": 2600, "response_format": {"type": "json_object"}}).encode()
    req = urllib.request.Request("https://api.deepseek.com/chat/completions", data=body,
                                 headers={"Content-Type": "application/json", "Authorization": "Bearer " + key})
    try:
        with urllib.request.urlopen(req, timeout=90) as response:
            raw = json.load(response)["choices"][0]["message"]["content"].strip()
        return _coerce_struct(json.loads(raw)), "IA"
    except Exception:
        return fallback_structure(source, keywords), "mise en page ATS"

_FONTS_REGISTERED = False

def _ensure_cv_fonts():
    global _FONTS_REGISTERED
    if _FONTS_REGISTERED:
        return True
    fonts = Path(__file__).resolve().parent / "fonts"
    try:
        pdfmetrics.registerFont(TTFont("Inter", str(fonts / "inter-400.ttf")))
        pdfmetrics.registerFont(TTFont("Inter-Med", str(fonts / "inter-500.ttf")))
        pdfmetrics.registerFont(TTFont("Inter-Sem", str(fonts / "inter-600.ttf")))
        pdfmetrics.registerFont(TTFont("Inter-Bold", str(fonts / "inter-700.ttf")))
        pdfmetrics.registerFont(TTFont("Sora-Bold", str(fonts / "sora-700.ttf")))
        pdfmetrics.registerFont(TTFont("Sora-Extra", str(fonts / "sora-800.ttf")))
        pdfmetrics.registerFontFamily("Inter", normal="Inter", bold="Inter-Bold", italic="Inter", boldItalic="Inter-Bold")
        pdfmetrics.registerFontFamily("Sora", normal="Sora-Bold", bold="Sora-Extra", italic="Sora-Bold", boldItalic="Sora-Extra")
        _FONTS_REGISTERED = True
        return True
    except Exception:
        return False

def build_ats_pdf(struct, validated_keywords):
    """CV 2 colonnes façon FlowCV : sidebar sombre + contenu principal blanc."""
    if not HAS_REPORTLAB:
        raise RuntimeError("reportlab absent")
    if not _ensure_cv_fonts():
        raise RuntimeError("polices CV introuvables")
    INK = HexColor("#111827"); MUT = HexColor("#6b7280"); ACC = HexColor("#4f46e5")
    DARK = HexColor("#0f172a"); WHITE = HexColor("#ffffff")
    SLT = HexColor("#e2e8f0"); SMUT = HexColor("#94a3b8"); SA = HexColor("#a5b4fc")
    st = {
        "name": ParagraphStyle("name", fontName="Sora-Extra", fontSize=26, leading=30, textColor=INK),
        "title": ParagraphStyle("title", fontName="Inter-Sem", fontSize=12, leading=16, textColor=ACC, spaceBefore=3),
        "avatar": ParagraphStyle("avatar", fontName="Sora-Extra", fontSize=15, leading=17, textColor=WHITE, alignment=TA_CENTER),
        "shead": ParagraphStyle("shead", fontName="Inter-Bold", fontSize=8.6, leading=11, textColor=SA, spaceBefore=13, spaceAfter=5),
        "sval": ParagraphStyle("sval", fontName="Inter", fontSize=8.4, leading=12, textColor=SLT),
        "stag": ParagraphStyle("stag", fontName="Inter-Med", fontSize=8.4, leading=12, textColor=SLT, spaceBefore=6),
        "mhead": ParagraphStyle("mhead", fontName="Sora-Bold", fontSize=12.5, leading=16, textColor=INK, spaceBefore=12, spaceAfter=5),
        "role": ParagraphStyle("role", fontName="Inter-Sem", fontSize=10.5, leading=14, textColor=INK, spaceBefore=7),
        "meta": ParagraphStyle("meta", fontName="Inter", fontSize=8.8, leading=12, textColor=MUT, spaceAfter=4),
        "body": ParagraphStyle("body", fontName="Inter", fontSize=9.3, leading=13.6, textColor=INK, spaceAfter=2),
        "bullet": ParagraphStyle("bullet", fontName="Inter", fontSize=9.3, leading=13.4, textColor=INK,
                                 leftIndent=10, bulletIndent=1, spaceAfter=2),
    }
    def rule_accent():
        return HRFlowable(width="100%", thickness=1.2, color=ACC, spaceBefore=1, spaceAfter=6)
    initials = "".join(p[0] for p in struct.get("nom", "").split()[:2]).upper() or "CV"
    contact = struct.get("contact") or {}
    sidebar = [Spacer(1, 5)]
    avatar = Table([[Paragraph(initials, st["avatar"])]], colWidths=[19*mm], rowHeights=[19*mm])
    avatar.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), ACC),
                                ("ROUNDEDCORNERS", [9.5*mm]*4),
                                ("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
    sidebar.append(avatar)
    sidebar.append(Paragraph(escape(struct.get("titre", "") or "Profil"), st["title"]))
    contact_rows = [("Email", contact.get("email")), ("Téléphone", contact.get("telephone")),
                    ("Localisation", contact.get("localisation")), ("GitHub", contact.get("github")),
                    ("LinkedIn", contact.get("linkedin"))]
    if any(v for _, v in contact_rows):
        sidebar.append(Paragraph("CONTACT", st["shead"]))
        for label, value in contact_rows:
            if value:
                sidebar.append(Paragraph(f'<font color="#94a3b8" size="7.2">{label.upper()}</font><br/>{escape(value)}', st["sval"]))
                sidebar.append(Spacer(1, 4))
    if struct.get("competences"):
        sidebar.append(Paragraph("COMPÉTENCES", st["shead"]))
        for group in struct["competences"]:
            if group.get("items"):
                sidebar.append(Paragraph(f'<font color="#94a3b8" size="7.2">{escape(group.get("groupe", "")).upper()}</font><br/>{escape(group["items"])}', st["stag"]))
    if validated_keywords:
        sidebar.append(Paragraph("MOTS-CLÉS CIBLÉS", st["shead"]))
        sidebar.append(Paragraph(f'<font color="#c7d2fe">{escape(" · ".join(validated_keywords))}</font>', st["stag"]))
    if struct.get("certifications"):
        sidebar.append(Paragraph("CERTIFICATIONS", st["shead"]))
        for c in struct["certifications"]:
            sidebar.append(Paragraph("• " + escape(c), st["sval"]))
    if struct.get("langues"):
        sidebar.append(Paragraph("LANGUES", st["shead"]))
        for lg in struct["langues"]:
            sidebar.append(Paragraph(escape(lg), st["sval"]))
    main = [Spacer(1, 4)]
    main.append(Paragraph(escape(struct.get("nom", "")), st["name"]))
    if struct.get("titre"):
        main.append(Paragraph(escape(struct["titre"]), st["title"]))
    if struct.get("profil"):
        main.append(Paragraph("PROFIL", st["mhead"])); main.append(rule_accent())
        main.append(Paragraph(escape(struct["profil"]), st["body"]))
    if struct.get("experiences"):
        main.append(Paragraph("EXPÉRIENCE PROFESSIONNELLE", st["mhead"])); main.append(rule_accent())
        for exp in struct["experiences"]:
            main.append(Paragraph(escape(exp.get("role", "")), st["role"]))
            if exp.get("meta"):
                main.append(Paragraph(escape(exp["meta"]), st["meta"]))
            for b in exp.get("bullets", []):
                main.append(Paragraph("• " + escape(b), st["bullet"]))
    if struct.get("formation"):
        main.append(Paragraph("FORMATION", st["mhead"])); main.append(rule_accent())
        for f in struct["formation"]:
            main.append(Paragraph(escape(f.get("role", "")), st["role"]))
            if f.get("meta"):
                main.append(Paragraph(escape(f["meta"]), st["meta"]))
    out = BytesIO()
    doc = SimpleDocTemplate(out, pagesize=A4, leftMargin=0, rightMargin=0, topMargin=0, bottomMargin=0,
                            title="CV — " + struct.get("nom", ""), author="MYNEWJOB")
    table = Table([[sidebar, main]], colWidths=[62*mm, 148*mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), DARK),
        ("BACKGROUND", (1, 0), (1, -1), WHITE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (0, -1), 20), ("RIGHTPADDING", (0, 0), (0, -1), 15),
        ("TOPPADDING", (0, 0), (0, -1), 20), ("BOTTOMPADDING", (0, 0), (0, -1), 18),
        ("LEFTPADDING", (1, 0), (1, -1), 26), ("RIGHTPADDING", (1, 0), (1, -1), 24),
        ("TOPPADDING", (1, 0), (1, -1), 22), ("BOTTOMPADDING", (1, 0), (1, -1), 18),
    ]))
    doc.build([table])
    return out.getvalue()

def rewrite_cv(pdf_b64, keywords, target=""):
    try:
        source = extract_pdf_text(pdf_b64)
        selected = []
        for keyword in keywords if isinstance(keywords, list) else []:
            clean = re.sub(r"[^\wÀ-ÿ +#./-]", "", str(keyword)).strip()[:50]
            if clean and normalize(clean) not in [normalize(k) for k in selected]:
                selected.append(clean)
        struct, mode = rewrite_cv_with_ai(source, selected[:12], str(target)[:100])
        pdf = build_ats_pdf(struct, selected[:12])
        return {"pdf": b64encode(pdf).decode(), "filename": "CV_optimise_ATS.pdf", "mode": mode,
                "mots_cles_valides": selected[:12]}
    except Exception as exc:
        return {"error": str(exc)}

def parse_cv(pdf_b64):
    """Extrait le texte d'un CV PDF, détecte le domaine et les compétences."""
    try:
        text = extract_pdf_text(pdf_b64)
    except Exception as exc:
        return {"error": str(exc)}
    dom, dom_n = detect_domain(text)
    return {"domaine": dom, "confiance": dom_n, "competences": extract_skills(text),
            "ats": analyze_ats(text, dom), "mots": len(text.split()), "apercu": text[:400]}

# ── Serveur HTTP ─────────────────────────────────────────────────────────────
MIME = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
        ".js": "application/javascript", ".png": "image/png", ".jpg": "image/jpeg",
        ".svg": "image/svg+xml", ".ico": "image/x-icon"}

class Handler(BaseHTTPRequestHandler):
    MAX_BODY = 8 * 1024 * 1024
    ALLOWED_ORIGINS = {"https://yukouf.github.io", "http://127.0.0.1:8123", "http://localhost:8123"}

    def _cors(self):
        origin = self.headers.get("Origin", "")
        if origin in self.ALLOWED_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Max-Age", "86400")

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _json(self, obj, code=200):
        b = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self._cors()
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
            elif u.path == "/api/feed":
                self._json(feed_offers((p.get("q") or [""])[0], (p.get("domaine") or [None])[0]))
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
        try:
            n = int(self.headers.get("Content-Length", 0))
        except (TypeError, ValueError):
            self._json({"error": "Content-Length invalide"}, 400)
            return
        if n > self.MAX_BODY:
            self._json({"error": "fichier trop volumineux (6 Mo maximum)"}, 413)
            return
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
        elif u.path == "/api/parse-cv":
            self._json(parse_cv(data.get("pdf", "")))
        elif u.path == "/api/rewrite-cv":
            self._json(rewrite_cv(data.get("pdf", ""), data.get("keywords", []), data.get("target", "")))
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
    host = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
    print(f"MYNEWJOB v2 sur http://{host}:{port} (site + API) — Ctrl+C pour arrêter")
    ThreadingHTTPServer((host, port), Handler).serve_forever()
