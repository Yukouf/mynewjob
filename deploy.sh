#!/usr/bin/env bash
# Déploiement MYNEWJOB sur un VPS (Ubuntu/Debian)
# Usage : sudo bash deploy.sh [port]  (défaut 8123)
set -euo pipefail

APP_DIR="/opt/mynewjob"
PORT="${1:-8123}"
SERVICE="mynewjob"

echo "==> Installation des dépendances"
apt-get update -q && apt-get install -yq python3 nginx

echo "==> Copie du site + backend dans $APP_DIR"
mkdir -p "$APP_DIR"
cp -r "$(dirname "$0")"/* "$APP_DIR/" 2>/dev/null || true
cp "$(dirname "$0")"/../backend/app.py "$APP_DIR/" 2>/dev/null || true
mkdir -p "$APP_DIR/data"

echo "==> Variables d'environnement (à compléter)"
if [ ! -f "$APP_DIR/.env" ]; then
  cat > "$APP_DIR/.env" <<'ENV'
# Clés API gratuites — voir README
FRANCETRAVAIL_ID=
FRANCETRAVAIL_SECRET=
LBA_API_TOKEN=
DEEPSEEK_API_KEY=
ENV
  echo "    fichier .env créé : éditez-le avec vos clés"
fi

echo "==> Service systemd"
cat > /etc/systemd/system/$SERVICE.service <<EOF
[Unit]
Description=MYNEWJOB backend
After=network.target

[Service]
WorkingDirectory=$APP_DIR
EnvironmentFile=$APP_DIR/.env
ExecStart=/usr/bin/python3 $APP_DIR/app.py $PORT
Restart=always
User=www-data

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now $SERVICE

echo "==> Reverse proxy nginx (port 80)"
cat > /etc/nginx/sites-available/$SERVICE <<EOF
server {
    listen 80;
    server_name _;
    location / {
        proxy_pass http://127.0.0.1:$PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
}
EOF
ln -sf /etc/nginx/sites-available/$SERVICE /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx

echo ""
echo "==> Terminé. Vérifications :"
echo "    systemctl status $SERVICE"
echo "    curl http://127.0.0.1:$PORT/api/health"
echo ""
echo "Le site est servi sur le port 80. Pour du HTTPS : certbot --nginx"
