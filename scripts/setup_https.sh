#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Public HTTPS for a node's lightserver (and explorer): nginx terminates TLS on 443 and forwards to
# the loopback listeners; lego gets the certificate from Let's Encrypt over HTTP-01 on port 80 and a
# systemd timer renews it. HTTPS_HOST may be a DNS name or a bare public IP: Let's Encrypt issues
# IP-address certificates, which are short-lived (160 h), hence the timer running twice a day (lego
# renews once half the lifetime is gone).
#
# Run as root (scripts/start.sh does it with PUBLIC_HTTPS=1). Environment:
#   HTTPS_HOST        public DNS name or IP address (required)
#   LIGHTSERVER_PORT  loopback lightserver port (required)
#   EXPLORER_PORT     loopback explorer port served at /; empty: none
#   ACME_EMAIL        optional contact address for the ACME account
#   ACME_STAGING=1    use the Let's Encrypt staging CA (untrusted certificates; for rehearsals)
#   ACME_PROFILE      certificate profile; default "shortlived" for an IP (required), none for a name
#   ACME_SERVER       another ACME directory URL (another CA, or a local test CA)
#   NGINX_RELOAD      command the renewal hook runs after installing a certificate
#   ROOT_PREFIX       write files under this directory and skip installs, lego and systemctl (tests)
set -euo pipefail

LEGO_VERSION=5.5.2
declare -A LEGO_SHA256=(
  [amd64]=2a35505089e7772c92e1e9ac144df91151ef2eca8568630db0ff91fca06d9bef
  [arm64]=15b14ec2ab14fde69cc8396eb0204c5ce4327e31a486953225a6059b26db3e8c
)

HTTPS_HOST="${HTTPS_HOST:-}"
LIGHTSERVER_PORT="${LIGHTSERVER_PORT:-}"
EXPLORER_PORT="${EXPLORER_PORT:-}"
ACME_EMAIL="${ACME_EMAIL:-}"
ACME_STAGING="${ACME_STAGING:-0}"
ACME_SERVER="${ACME_SERVER:-}"
NGINX_RELOAD="${NGINX_RELOAD:-nginx -t -q && systemctl reload nginx}"
ROOT_PREFIX="${ROOT_PREFIX:-}"
NGINX_BIN="${NGINX_BIN:-nginx}"

log() { printf '[https] %s\n' "$*"; }
die() { log "error: $*"; exit 1; }

[[ -n "${HTTPS_HOST}" ]] || die "HTTPS_HOST is required"
[[ "${LIGHTSERVER_PORT}" =~ ^[0-9]+$ ]] || die "LIGHTSERVER_PORT is required"
[[ -z "${EXPLORER_PORT}" || "${EXPLORER_PORT}" =~ ^[0-9]+$ ]] || die "EXPLORER_PORT must be a port"
# A host name or IP literal only: it goes into nginx config and a lego command line.
[[ "${HTTPS_HOST}" =~ ^[A-Za-z0-9.:-]+$ ]] || die "HTTPS_HOST has unexpected characters"

is_ip=0
if [[ "${HTTPS_HOST}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ || "${HTTPS_HOST}" == *:* ]]; then is_ip=1; fi
ACME_PROFILE="${ACME_PROFILE-$([[ ${is_ip} == 1 ]] && echo shortlived)}"

ACME_DIR="${ROOT_PREFIX}/var/lib/finalis/acme"
WEBROOT="${ACME_DIR}/webroot"
# Account and certificates per CA: a still-valid staging certificate must not make a production run
# "not due for renewal", or the other way round.
if [[ -n "${ACME_SERVER}" ]]; then
  LEGO_PATH="${ACME_DIR}/custom-$(printf '%s' "${ACME_SERVER}" | sha256sum | cut -c1-12)"
elif [[ "${ACME_STAGING}" == 1 ]]; then
  LEGO_PATH="${ACME_DIR}/staging"
else
  LEGO_PATH="${ACME_DIR}/production"
fi
TLS_DIR="${ROOT_PREFIX}/etc/finalis/tls"
HOOK="${ROOT_PREFIX}/usr/local/lib/finalis/https-deploy-hook.sh"
LEGO="${ROOT_PREFIX}/usr/local/bin/lego"
NGINX_CONF="${ROOT_PREFIX}/etc/nginx/conf.d/finalis-https.conf"
UNIT_DIR="${ROOT_PREFIX}/etc/systemd/system"

ipv6_listen=0
[[ -f /proc/net/if_inet6 ]] && ipv6_listen=1

install_packages() {
  [[ -n "${ROOT_PREFIX}" ]] && return 0
  if ! command -v nginx >/dev/null 2>&1; then
    log "Installing nginx..."
    if command -v apt-get >/dev/null 2>&1; then
      DEBIAN_FRONTEND=noninteractive apt-get install -y nginx >/dev/null
    elif command -v dnf >/dev/null 2>&1; then
      dnf install -y nginx >/dev/null
    else
      die "install nginx first (no apt-get or dnf)"
    fi
  fi
  if [[ -x "${LEGO}" ]] && "${LEGO}" --version 2>/dev/null | grep -q "${LEGO_VERSION}"; then return 0; fi
  local arch
  case "$(uname -m)" in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) die "no pinned lego build for $(uname -m)" ;;
  esac
  log "Installing lego ${LEGO_VERSION} (${arch})..."
  local tmp; tmp="$(mktemp -d)"
  local tarball="lego_v${LEGO_VERSION}_linux_${arch}.tar.gz"
  curl -fsSL --max-time 120 -o "${tmp}/${tarball}" \
    "https://github.com/go-acme/lego/releases/download/v${LEGO_VERSION}/${tarball}"
  echo "${LEGO_SHA256[${arch}]}  ${tmp}/${tarball}" | sha256sum -c --quiet - || die "lego download checksum mismatch"
  tar -xzf "${tmp}/${tarball}" -C "${tmp}" lego
  install -m 0755 "${tmp}/lego" "${LEGO}"
  rm -rf "${tmp}"
}

write_hook() {
  mkdir -p "$(dirname "${HOOK}")" "${TLS_DIR}"
  cat > "${HOOK}" <<EOF
#!/bin/sh
# lego deploy hook: publish the new certificate to nginx.
set -eu
install -m 0644 "\${LEGO_HOOK_CERT_PATH}" "${TLS_DIR}/fullchain.pem"
install -m 0600 "\${LEGO_HOOK_CERT_KEY_PATH}" "${TLS_DIR}/privkey.pem"
if [ -f "${NGINX_CONF}.full" ]; then cp "${NGINX_CONF}.full" "${NGINX_CONF}"; fi
${NGINX_RELOAD}
EOF
  chmod 0755 "${HOOK}"
}

# $1 = 1: also the TLS server (needs the certificate in place).
write_nginx_conf() {
  local with_tls="$1" out="$2"
  local v6_80="" v6_443=""
  if [[ ${ipv6_listen} == 1 ]]; then
    v6_80="    listen [::]:80;"
    v6_443="    listen [::]:443 ssl;"
  fi
  local server_name="${HTTPS_HOST}"
  mkdir -p "$(dirname "${out}")"
  {
    cat <<EOF
# Generated by finalis scripts/setup_https.sh; rewritten on every run.
limit_req_zone \$binary_remote_addr zone=finalis_https_rpc:10m rate=20r/s;
limit_req_zone \$binary_remote_addr zone=finalis_https_web:10m rate=60r/s;
limit_conn_zone \$binary_remote_addr zone=finalis_https_conn:10m;

server {
    listen 80;
${v6_80}
    server_name ${server_name};
    location /.well-known/acme-challenge/ {
        root ${WEBROOT};
    }
    location / {
        return 301 https://\$host\$request_uri;
    }
}
EOF
    if [[ "${with_tls}" == 1 ]]; then
      cat <<EOF

server {
    listen 443 ssl;
${v6_443}
    server_name ${server_name};
    ssl_certificate     ${TLS_DIR}/fullchain.pem;
    ssl_certificate_key ${TLS_DIR}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:finalis_tls:10m;
    add_header Strict-Transport-Security "max-age=31536000" always;
    limit_conn finalis_https_conn 16;

    # The lightserver and explorer trust the client-IP header from this proxy only (--trusted-proxy
    # 127.0.0.1/32), so every location overwrites both kinds (X-Real-IP; CF-Connecting-IP for a host
    # whose explorer also sits behind a Cloudflare tunnel) and drops the mTLS header no client may set.
    location = /rpc {
        limit_req zone=finalis_https_rpc burst=60 nodelay;
        client_max_body_size 2m;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header CF-Connecting-IP \$remote_addr;
        proxy_set_header X-Finalis-Mtls-Verified "";
        proxy_pass http://127.0.0.1:${LIGHTSERVER_PORT};
    }
EOF
      if [[ -n "${EXPLORER_PORT}" ]]; then
        cat <<EOF
    location / {
        limit_req zone=finalis_https_web burst=120 nodelay;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header CF-Connecting-IP \$remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Finalis-Mtls-Verified "";
        proxy_pass http://127.0.0.1:${EXPLORER_PORT};
    }
EOF
      else
        echo "    location / { return 404; }"
      fi
      echo "}"
    fi
  } > "${out}"
}

lego_args() {
  local -a a=(run --accept-tos --domains "${HTTPS_HOST}" --http --http.webroot "${WEBROOT}" --path "${LEGO_PATH}"
              --cert.name finalis --deploy-hook "${HOOK}")
  [[ -n "${ACME_EMAIL}" ]] && a+=(--email "${ACME_EMAIL}")
  if [[ -n "${ACME_SERVER}" ]]; then
    a+=(--server "${ACME_SERVER}")
  elif [[ "${ACME_STAGING}" == 1 ]]; then
    a+=(--server letsencrypt-staging)
  fi
  [[ -n "${ACME_PROFILE}" ]] && a+=(--profile "${ACME_PROFILE}")
  printf '%q ' "${a[@]}"
}

write_units() {
  mkdir -p "${UNIT_DIR}"
  cat > "${UNIT_DIR}/finalis-acme-renew.service" <<EOF
[Unit]
Description=Renew the Finalis public HTTPS certificate
After=network-online.target nginx.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/sh -c '${LEGO} $(lego_args)'
EOF
  cat > "${UNIT_DIR}/finalis-acme-renew.timer" <<EOF
[Unit]
Description=Renew the Finalis public HTTPS certificate twice a day

[Timer]
OnCalendar=*-*-* 00,12:00:00
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF
}

reload_nginx() {
  [[ -n "${ROOT_PREFIX}" ]] && return 0
  "${NGINX_BIN}" -t -q || die "nginx rejected ${NGINX_CONF}"
  systemctl enable --now nginx >/dev/null 2>&1 || true
  systemctl reload nginx
}

main() {
  log "Host ${HTTPS_HOST}$([[ ${is_ip} == 1 ]] && echo " (IP-address certificate, profile ${ACME_PROFILE})")$([[ ${ACME_STAGING} == 1 ]] && echo ", STAGING CA")"
  install_packages
  mkdir -p "${WEBROOT}" "${TLS_DIR}"
  chmod 0700 "${TLS_DIR}"
  write_hook
  write_nginx_conf 1 "${NGINX_CONF}.full"
  if [[ -s "${TLS_DIR}/fullchain.pem" && -s "${TLS_DIR}/privkey.pem" ]]; then
    cp "${NGINX_CONF}.full" "${NGINX_CONF}"
  else
    # No certificate yet: port 80 only, for the challenge; the deploy hook installs the full config.
    write_nginx_conf 0 "${NGINX_CONF}"
  fi
  reload_nginx
  write_units
  if [[ -n "${ROOT_PREFIX}" ]]; then
    log "ROOT_PREFIX set: files written under ${ROOT_PREFIX}; skipped lego and systemctl."
    return 0
  fi
  log "Requesting the certificate (HTTP-01 on port 80)..."
  # shellcheck disable=SC2046
  eval "${LEGO} $(lego_args)" || die "certificate request failed: is port 80 reachable from the internet?"
  systemctl daemon-reload
  systemctl enable --now finalis-acme-renew.timer >/dev/null
  log "HTTPS ready: https://$([[ ${HTTPS_HOST} == *:* ]] && echo "[${HTTPS_HOST}]" || echo "${HTTPS_HOST}")/rpc (renewal timer finalis-acme-renew.timer)"
}

main "$@"
