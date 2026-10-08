#!/usr/bin/env bash
# Prepara un Ubuntu LIMPIO (22.04/24.04) para alojar Apunte: usuario de despliegue, SSH solo con llave,
# firewall (SSH + 80/443 solo desde Cloudflare), fail2ban, actualizaciones automáticas, Docker, restic y
# las carpetas de secretos. Es idempotente: se puede repetir.
#
#   sudo DEPLOY_USER=deploy DEPLOY_PUBKEY="ssh-ed25519 AAAA… usuario@equipo" ./setup-server.sh
#
# ¡Antes de cerrar la sesión actual, abre otra y comprueba que entras como $DEPLOY_USER con tu llave!
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "ejecuta con sudo" >&2; exit 1; }
DEPLOY_USER="${DEPLOY_USER:-deploy}"
: "${DEPLOY_PUBKEY:?falta DEPLOY_PUBKEY (tu clave pública SSH)}"
[[ "$DEPLOY_PUBKEY" == ssh-* ]] || { echo "DEPLOY_PUBKEY no parece una clave pública SSH" >&2; exit 1; }
export DEBIAN_FRONTEND=noninteractive

apt-get update -y
apt-get install -y --no-install-recommends ca-certificates curl gnupg ufw fail2ban unattended-upgrades restic postgresql-client jq

# ── Usuario de despliegue ──
id "$DEPLOY_USER" >/dev/null 2>&1 || adduser --disabled-password --gecos "" "$DEPLOY_USER"
install -d -m 700 -o "$DEPLOY_USER" -g "$DEPLOY_USER" "/home/$DEPLOY_USER/.ssh"
grep -qxF "$DEPLOY_PUBKEY" "/home/$DEPLOY_USER/.ssh/authorized_keys" 2>/dev/null || echo "$DEPLOY_PUBKEY" >> "/home/$DEPLOY_USER/.ssh/authorized_keys"
chown "$DEPLOY_USER:$DEPLOY_USER" "/home/$DEPLOY_USER/.ssh/authorized_keys"; chmod 600 "/home/$DEPLOY_USER/.ssh/authorized_keys"

# ── SSH: solo llave, sin root ──
cat > /etc/ssh/sshd_config.d/99-apunte.conf <<SSH
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AllowUsers $DEPLOY_USER
MaxAuthTries 3
LoginGraceTime 20
X11Forwarding no
SSH
sshd -t && systemctl reload ssh

# ── Docker (repositorio oficial) ──
if ! command -v docker >/dev/null; then
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" > /etc/apt/sources.list.d/docker.list
  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
fi
usermod -aG docker "$DEPLOY_USER"
# Docker se salta ufw cuando se publican puertos: por eso solo Caddy publica (80/443) y las reglas de
# Cloudflare van en la cadena DOCKER-USER, que sí se aplica.
cat > /etc/docker/daemon.json <<'JSON'
{ "iptables": true, "log-driver": "json-file", "log-opts": { "max-size": "10m", "max-file": "5" }, "no-new-privileges": true, "live-restore": true }
JSON
systemctl restart docker

# ── Firewall ──
CF_V4="$(curl -fsS https://www.cloudflare.com/ips-v4)"; CF_V6="$(curl -fsS https://www.cloudflare.com/ips-v6)"
ufw --force reset
ufw default deny incoming; ufw default allow outgoing
ufw limit 22/tcp
for r in $CF_V4 $CF_V6; do ufw allow from "$r" to any port 80,443 proto tcp; done
ufw --force enable
# DOCKER-USER: lo publicado por Docker (80/443 de Caddy) solo acepta Cloudflare.
install -d /etc/apunte
cat > /usr/local/sbin/apunte-docker-fw <<FW
#!/usr/bin/env bash
set -e
iptables -F DOCKER-USER
iptables -A DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
iptables -A DOCKER-USER -i docker0 -j RETURN
iptables -A DOCKER-USER -i br+ -j RETURN
$(for r in $CF_V4; do echo "iptables -A DOCKER-USER -s $r -p tcp -m multiport --dports 80,443 -j RETURN"; done)
iptables -A DOCKER-USER -p tcp -m multiport --dports 80,443 -j DROP
iptables -A DOCKER-USER -j RETURN
FW
chmod 700 /usr/local/sbin/apunte-docker-fw
cat > /etc/systemd/system/apunte-docker-fw.service <<UNIT
[Unit]
Description=Reglas de Cloudflare para los puertos publicados por Docker
After=docker.service
Requires=docker.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/apunte-docker-fw
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload && systemctl enable --now apunte-docker-fw.service

# ── fail2ban y actualizaciones de seguridad automáticas ──
cat > /etc/fail2ban/jail.d/apunte.conf <<'F2B'
[sshd]
enabled = true
maxretry = 4
bantime = 1h
findtime = 10m
F2B
systemctl enable --now fail2ban && systemctl restart fail2ban
dpkg-reconfigure -f noninteractive unattended-upgrades

# ── Carpetas de secretos y despliegue ──
install -d -m 700 -o root -g root /etc/apunte
install -d -m 755 -o "$DEPLOY_USER" -g "$DEPLOY_USER" /opt/apunte /opt/apunte/state
echo "Servidor listo. Siguiente: copia los .env a /etc/apunte (chmod 600) y sigue docs/deploy.md."
