# MYNEWJOB

Moteur de recherche d'alternance, de stage et de CDI : offres agrégées, score de compatibilité, marché caché, lettres et CV assistés par IA.

## Contenu

- `index.html`, `feed.html`, `marche-cache.html`, `ia.html`, `suivi.html` : site statique (5 pages)
- `mentions-legales.html`, `cgu.html`, `confidentialite.html` : pages légales
- `style.css` : design commun
- `backend/app.py` : API (recherche, score, lettres, comptes, suivi) + sert le site
- `deploy.sh` : déploiement VPS (systemd + nginx)

## Démarrage local

```bash
cd backend
DEEPSEEK_API_KEY=xxx python3 app.py 8123
# → http://localhost:8123 (site + API)
```

## Déploiement VPS

```bash
sudo bash deploy.sh
```

## Clés API (gratuites, à créer)

| Service | Où | Variable |
|---|---|---|
| France Travail | api.francetravail.io (compte partenaire) | `FRANCETRAVAIL_ID`, `FRANCETRAVAIL_SECRET` |
| La Bonne Alternance | api.apprentissage.beta.gouv.fr | `LBA_API_TOKEN` |
| DeepSeek | platform.deepseek.com | `DEEPSEEK_API_KEY` |

Sans clés, la recherche fonctionne sur un jeu de test.

## API

| Route | Description |
|---|---|
| `GET /api/search?q=&city=` | Offres (France Travail, LBA, sinon jeu de test) |
| `GET /api/score?text=` | Score de compatibilité vs profil |
| `POST /api/letter` | Lettre de motivation (DeepSeek) |
| `POST /api/register` / `POST /api/login` | Comptes (token Bearer) |
| `POST /api/follow` / `POST /api/unfollow` | Suivre une offre |
| `GET /api/follows` | Candidatures suivies |
