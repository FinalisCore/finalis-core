#!/usr/bin/env bash
# SPDX-License-Identifier: MIT

set -euo pipefail

PREFIX="${1:-/opt/finalis-core}"
SYSTEMD_DIR="${2:-/etc/systemd/system}"
ETC_DIR="${3:-/etc/finalis-mint}"
LIBEXEC_DIR="${4:-/usr/local/libexec}"
STATE_DIR="${5:-/var/lib/finalis-mint}"
RUN_DIR="${6:-/run/finalis-mint}"

install -d "$SYSTEMD_DIR" "$ETC_DIR" "$ETC_DIR/secrets.d" "$LIBEXEC_DIR" "$STATE_DIR" "$RUN_DIR"
install -m 0644 services/finalis-mint/systemd/finalis-mint-server.service "$SYSTEMD_DIR/finalis-mint-server.service"
install -m 0644 services/finalis-mint/systemd/finalis-mint-worker.service "$SYSTEMD_DIR/finalis-mint-worker.service"
install -m 0644 services/finalis-mint/systemd/finalis-mint.env.example "$ETC_DIR/finalis-mint.env"
install -m 0644 services/finalis-mint/systemd/finalis-mint.tmpfiles.conf "$ETC_DIR/finalis-mint.tmpfiles.conf"
install -m 0755 services/finalis-mint/secret_helper.py "$LIBEXEC_DIR/finalis-mint-secret-helper"
echo "Installed unit files into $SYSTEMD_DIR, helper into $LIBEXEC_DIR/finalis-mint-secret-helper, and env template into $ETC_DIR/finalis-mint.env"
